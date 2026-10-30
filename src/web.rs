//! HTTP layer: routing, security middleware, authentication extractors and API handlers.

use crate::audit::Audit;
use crate::auth::{self, Auth, LoginError, Session};
use crate::config::{Config, Role};
use crate::plugins::runtime::{self, ExecPolicy, SaveError};
use crate::plugins::{Registry, Source};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, FromRequestParts, Path, Query, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[derive(RustEmbed)]
#[folder = "web/"]
struct Assets;

pub struct AppState {
    pub cfg: Config,
    pub auth: Auth,
    pub registry: Registry,
    pub audit: Audit,
    pub plugin_errors: Vec<String>,
    pub backup_dir: PathBuf,
    pub pol: ExecPolicy,
    pub terminals: AtomicUsize,
}

pub type Shared = Arc<AppState>;

pub fn router(state: Shared) -> Router {
    let api = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/session", get(session))
        .route("/apps", get(list_apps))
        .route("/apps/{id}", get(app_detail))
        .route("/apps/{id}/actions/{action}", post(run_action))
        .route("/apps/{id}/file", get(read_file).put(write_file))
        .route("/apps/{id}/logs/{index}", get(read_log))
        .route("/apps/{id}/views/{view}", get(view_data))
        .route("/apps/{id}/views/{view}/actions/{action}", post(view_action))
        .route("/rescan", post(rescan))
        .route("/audit", get(audit_log))
        .route("/terminal", get(crate::terminal::handler))
        .fallback(|| async { err(StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::map_response(no_store));
    Router::new()
        .nest("/api", api)
        .fallback(static_asset)
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(state.clone(), security_headers))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

async fn security_headers(
    State(st): State<Shared>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    // 'unsafe-inline' for styles only: xterm.js injects <style> elements. No inline scripts are allowed.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
    );
    if st.cfg.secure_cookies() {
        h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    }
    res
}

async fn no_store(mut res: Response) -> Response {
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// ---------------------------------------------------------------------------
// Request context: client IP, origin check, session
// ---------------------------------------------------------------------------

pub fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// Real client IP. `X-Forwarded-For` is only honoured from configured proxies.
pub fn client_ip(cfg: &Config, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    if !cfg.server.behind_proxy || !cfg.server.trusted_proxies.contains(&peer_ip) {
        return peer_ip;
    }
    let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else { return peer_ip };
    // Walk from the right; the first hop that isn't a trusted proxy is the client.
    xff.split(',')
        .rev()
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .find(|ip| !cfg.server.trusted_proxies.contains(ip))
        .unwrap_or(peer_ip)
}

fn expected_origin(cfg: &Config, headers: &HeaderMap) -> Option<String> {
    if let Some(o) = &cfg.server.public_origin {
        return Some(o.clone());
    }
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let scheme = if cfg.secure_cookies() { "https" } else { "http" };
    Some(format!("{scheme}://{host}"))
}

/// Cross-site request protection for anything that changes state (and the WebSocket).
pub fn origin_ok(cfg: &Config, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return false };
    expected_origin(cfg, headers).is_some_and(|e| e.eq_ignore_ascii_case(origin))
}

fn cookie_name(cfg: &Config) -> &'static str {
    if cfg.secure_cookies() { auth::SESSION_COOKIE_SECURE } else { auth::SESSION_COOKIE_PLAIN }
}

fn session_token(cfg: &Config, headers: &HeaderMap) -> Option<String> {
    let name = cookie_name(cfg);
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// Authenticated request. Non-GET requests additionally require a matching
/// Origin and the session's CSRF token header.
pub struct Authed {
    pub session: Session,
    pub token: String,
    pub ip: IpAddr,
}

/// Same as `Authed` but requires the admin role.
pub struct Admin(pub Authed);

impl<S> FromRequestParts<S> for Authed
where
    Shared: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let st = Shared::from_ref(state);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let ip = client_ip(&st.cfg, peer, &parts.headers);
        let token = session_token(&st.cfg, &parts.headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not logged in"))?;
        let session = st.auth.session(&token).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "session expired"))?;
        let safe = matches!(parts.method, Method::GET | Method::HEAD);
        let is_ws = parts.headers.get(header::UPGRADE).is_some();
        if !safe || is_ws {
            if !origin_ok(&st.cfg, &parts.headers) {
                st.audit.log(&session.user, ip, "csrf.origin", parts.uri.path(), false);
                return Err(err(StatusCode::FORBIDDEN, "bad origin"));
            }
        }
        if !safe {
            let sent = parts.headers.get(auth::CSRF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
            if !bool::from(subtle::ConstantTimeEq::ct_eq(sent.as_bytes(), session.csrf.as_bytes())) {
                st.audit.log(&session.user, ip, "csrf.token", parts.uri.path(), false);
                return Err(err(StatusCode::FORBIDDEN, "bad csrf token"));
            }
        }
        Ok(Authed { session, token, ip })
    }
}

impl<S> FromRequestParts<S> for Admin
where
    Shared: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let a = Authed::from_request_parts(parts, state).await?;
        if a.session.role != Role::Admin {
            return Err(err(StatusCode::FORBIDDEN, "admin role required"));
        }
        Ok(Admin(a))
    }
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
    #[serde(default)]
    totp: Option<String>,
}

async fn login(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    let ip = client_ip(&st.cfg, peer, &headers);
    if !origin_ok(&st.cfg, &headers) {
        return err(StatusCode::FORBIDDEN, "bad origin");
    }
    if req.username.len() > 64 || req.password.len() > 1024 {
        return err(StatusCode::BAD_REQUEST, "input too long");
    }
    let st2 = st.clone();
    let (u, p, t) = (req.username.clone(), req.password, req.totp);
    // Argon2 is CPU-heavy; keep it off the async workers.
    let result = tokio::task::spawn_blocking(move || st2.auth.login(ip, &u, &p, t.as_deref())).await;
    match result {
        Ok(Ok((token, s))) => {
            st.audit.log(&s.user, ip, "login", "", true);
            let mut cookie = format!("{}={token}; Path=/; HttpOnly; SameSite=Strict", cookie_name(&st.cfg));
            if st.cfg.secure_cookies() {
                cookie.push_str("; Secure");
            }
            let mut res = Json(session_json(&st, &s)).into_response();
            res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
            res
        }
        Ok(Err(LoginError::TotpRequired)) => {
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "TOTP code required", "totp_required": true}))).into_response()
        }
        Ok(Err(LoginError::RateLimited)) => {
            st.audit.log(&req.username, ip, "login.ratelimited", "", false);
            err(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts, try again later")
        }
        Ok(Err(LoginError::Invalid)) => {
            st.audit.log(&req.username, ip, "login", "invalid credentials", false);
            err(StatusCode::UNAUTHORIZED, "invalid username, password or code")
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "login failed"),
    }
}

fn session_json(st: &AppState, s: &Session) -> Value {
    json!({
        "user": s.user,
        "role": s.role,
        "csrf": s.csrf,
        "terminal": terminal_available(st) && s.role == Role::Admin,
        "hostname": std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// The terminal is available when enabled in config AND the terminal plugin is loaded.
pub fn terminal_available(st: &AppState) -> bool {
    st.cfg.terminal.enabled && st.registry.get("terminal").is_some()
}

async fn logout(State(st): State<Shared>, a: Authed) -> Response {
    st.auth.logout(&a.token);
    st.audit.log(&a.session.user, a.ip, "logout", "", true);
    let mut cookie = format!("{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0", cookie_name(&st.cfg));
    if st.cfg.secure_cookies() {
        cookie.push_str("; Secure");
    }
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    res
}

async fn session(State(st): State<Shared>, a: Authed) -> Response {
    Json(session_json(&st, &a.session)).into_response()
}

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

async fn list_apps(State(st): State<Shared>, a: Authed) -> Response {
    let admin = a.session.role == Role::Admin;
    let futs = st.registry.plugins.iter().map(|p| {
        let st = st.clone();
        async move {
            let m = &p.manifest;
            let d = st.registry.detection(&m.id).await;
            let state = if d.detected { runtime::service_status(m).await.map(|s| s.active) } else { None };
            json!({
                "id": m.id, "name": m.name, "description": m.description, "category": m.category,
                "icon": m.icon, "detected": d.detected, "version": d.version, "state": state,
                "views": if admin && d.detected { serde_json::to_value(runtime::views(m)).unwrap() } else { json!([]) },
            })
        }
    });
    Json(futures_util::future::join_all(futs).await).into_response()
}

async fn app_detail(State(st): State<Shared>, a: Authed, Path(id): Path<String>) -> Response {
    let Some(p) = st.registry.get(&id) else { return err(StatusCode::NOT_FOUND, "unknown app") };
    let m = &p.manifest;
    let d = st.registry.detection(&id).await;
    let admin = a.session.role == Role::Admin;
    let service = if d.detected { runtime::service_status(m).await } else { None };
    // Info probes, file lists and logs can reveal sensitive data: admin only.
    let info = if admin && d.detected { runtime::info(p, st.pol).await } else { vec![] };
    let source = match &p.source {
        Source::Native => "native".to_string(),
        Source::Builtin => "builtin".to_string(),
        Source::File(path) => path.display().to_string(),
    };
    Json(json!({
        "id": m.id, "name": m.name, "description": m.description, "category": m.category, "icon": m.icon,
        "detected": d.detected, "evidence": d.evidence, "version": d.version, "source": source,
        "service": service,
        "info": info.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "actions": runtime::actions(m),
        "files": if admin { serde_json::to_value(runtime::files(m)).unwrap() } else { json!([]) },
        "logs": if admin { serde_json::to_value(runtime::logs(m)).unwrap() } else { json!([]) },
        "views": if admin { serde_json::to_value(runtime::views(m)).unwrap() } else { json!([]) },
    }))
    .into_response()
}

/// Admin + plugin exists + application is detected. Undetected apps are never acted on.
async fn managed<'a>(st: &'a AppState, id: &str) -> Result<&'a crate::plugins::Plugin, Response> {
    let p = st.registry.get(id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown app"))?;
    if !st.registry.is_detected(id).await {
        return Err(err(StatusCode::CONFLICT, "application is not detected on this host"));
    }
    Ok(p)
}

#[derive(Deserialize)]
struct ActionReq {
    #[serde(default)]
    params: HashMap<String, String>,
}

async fn run_action(
    State(st): State<Shared>,
    Admin(a): Admin,
    Path((id, action)): Path<(String, String)>,
    Json(req): Json<ActionReq>,
) -> Response {
    let p = match managed(&st, &id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detail = format!("{id}/{action} {:?}", req.params);
    match runtime::run_action(&p.manifest, &action, &req.params, st.pol).await {
        Ok(out) => {
            st.audit.log(&a.session.user, a.ip, "action", format!("{detail} exit={:?}", out.code), out.success());
            Json(out).into_response()
        }
        Err(e) => {
            st.audit.log(&a.session.user, a.ip, "action", format!("{detail}: {e:#}"), false);
            err(StatusCode::BAD_REQUEST, format!("{e:#}"))
        }
    }
}

#[derive(Deserialize)]
struct PathQuery {
    path: String,
}

async fn read_file(State(st): State<Shared>, Admin(a): Admin, Path(id): Path<String>, Query(q): Query<PathQuery>) -> Response {
    let p = match managed(&st, &id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match runtime::read_file(&p.manifest, &q.path) {
        Ok(f) => {
            st.audit.log(&a.session.user, a.ip, "file.read", &q.path, true);
            Json(f).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct WriteReq {
    path: String,
    content: String,
    sha256: String,
}

async fn write_file(State(st): State<Shared>, Admin(a): Admin, Path(id): Path<String>, Json(req): Json<WriteReq>) -> Response {
    let p = match managed(&st, &id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let res = runtime::write_file(&p.manifest, &req.path, &req.content, &req.sha256, &st.backup_dir, st.pol).await;
    match res {
        Ok(r) => {
            st.audit.log(&a.session.user, a.ip, "file.write", format!("{} backup={}", req.path, r.backup), true);
            Json(r).into_response()
        }
        Err(SaveError::Conflict) => err(StatusCode::CONFLICT, "file changed on disk since it was opened; reload it first"),
        Err(SaveError::Invalid(out)) => {
            st.audit.log(&a.session.user, a.ip, "file.write", format!("{} rejected by validation", req.path), false);
            (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "validation failed; previous content restored", "validation": out})))
                .into_response()
        }
        Err(SaveError::Other(e)) => {
            st.audit.log(&a.session.user, a.ip, "file.write", format!("{}: {e:#}", req.path), false);
            err(StatusCode::BAD_REQUEST, format!("{e:#}"))
        }
    }
}

async fn read_log(State(st): State<Shared>, Admin(_a): Admin, Path((id, index)): Path<(String, usize)>) -> Response {
    let p = match managed(&st, &id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match runtime::read_log(&p.manifest, index, st.pol).await {
        Ok(text) => Json(json!({ "text": text })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

async fn view_data(State(st): State<Shared>, Admin(_a): Admin, Path((id, view)): Path<(String, String)>) -> Response {
    let p = match managed(&st, &id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match runtime::view_data(p, &view, st.pol).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct RowReq {
    row: Value,
}

async fn view_action(
    State(st): State<Shared>,
    Admin(a): Admin,
    Path((id, view, action)): Path<(String, String, String)>,
    Json(req): Json<RowReq>,
) -> Response {
    let p = match managed(&st, &id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let detail = format!("{id}/{view}/{action} {}", req.row.to_string().chars().take(300).collect::<String>());
    match runtime::view_action(p, &view, &action, &req.row, st.pol).await {
        Ok(msg) => {
            st.audit.log(&a.session.user, a.ip, "view.action", &detail, true);
            Json(json!({ "message": msg })).into_response()
        }
        Err(e) => {
            st.audit.log(&a.session.user, a.ip, "view.action", format!("{detail}: {e:#}"), false);
            err(StatusCode::BAD_REQUEST, format!("{e:#}"))
        }
    }
}

async fn rescan(State(st): State<Shared>, Admin(a): Admin) -> Response {
    st.registry.rescan().await;
    st.audit.log(&a.session.user, a.ip, "rescan", "", true);
    Json(json!({"ok": true})).into_response()
}

async fn audit_log(State(st): State<Shared>, Admin(_a): Admin) -> Response {
    Json(json!({ "entries": st.audit.recent(), "plugin_errors": st.plugin_errors })).into_response()
}

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------

async fn static_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let cache = if path == "index.html" { "no-cache" } else { "public, max-age=300" };
            ([(header::CONTENT_TYPE, mime.as_ref().to_string()), (header::CACHE_CONTROL, cache.to_string())], file.data)
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> Config {
        toml::from_str(&format!("[server]\n{extra}")).unwrap()
    }

    #[test]
    fn xff_only_from_trusted_proxy() {
        let c = cfg("behind_proxy = true\ntrusted_proxies = [\"127.0.0.1\"]\n");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4".parse().unwrap());
        let proxy: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let direct: SocketAddr = "9.9.9.9:5000".parse().unwrap();
        assert_eq!(client_ip(&c, proxy, &h), "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&c, direct, &h), "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&cfg(""), proxy, &h), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn origin_checks() {
        let c = cfg("");
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "127.0.0.1:8443".parse().unwrap());
        assert!(!origin_ok(&c, &h), "missing origin must fail");
        h.insert(header::ORIGIN, "http://127.0.0.1:8443".parse().unwrap());
        assert!(origin_ok(&c, &h));
        h.insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!origin_ok(&c, &h));
        let c = cfg("public_origin = \"https://admin.example.com\"\n");
        h.insert(header::ORIGIN, "https://admin.example.com".parse().unwrap());
        assert!(origin_ok(&c, &h));
    }
}
