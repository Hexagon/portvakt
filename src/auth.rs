//! Authentication: Argon2id passwords, optional TOTP, server-side sessions,
//! CSRF tokens and login rate limiting.
//!
//! Design notes (see docs/SECURITY.md):
//! - Session tokens are 256-bit random values. Only their SHA-256 is kept in memory,
//!   so a memory dump of the session table cannot be replayed as cookies.
//! - Every state-changing request needs the per-session CSRF token in a header
//!   (in addition to SameSite=Strict cookies and an Origin check).
//! - Unknown usernames still run a full Argon2 verification to avoid user enumeration
//!   via timing.

use crate::config::{Config, Role, User};
use anyhow::{Result, anyhow};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SESSION_COOKIE_SECURE: &str = "__Host-portvakt";
pub const SESSION_COOKIE_PLAIN: &str = "portvakt";
pub const CSRF_HEADER: &str = "x-portvakt-csrf";

pub fn valid_username(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

pub fn hash_password(password: &str) -> Result<String> {
    let hash = Argon2::default().hash_password(password.as_bytes()).map_err(|e| anyhow!("hashing failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else { return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill(&mut buf[..]);
    hex::encode(buf)
}

fn token_key(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238, SHA-1, 6 digits, 30 s step, ±1 step skew)
// ---------------------------------------------------------------------------

pub fn generate_totp_secret() -> String {
    let mut buf = [0u8; 20];
    rand::rng().fill(&mut buf[..]);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf)
}

fn hotp(key: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin =
        u32::from_be_bytes([digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]]) & 0x7fff_ffff;
    bin % 1_000_000
}

pub fn verify_totp(secret_b32: &str, code: &str, unix_time: u64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Some(key) = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32.trim_end_matches('='))
    else {
        return false;
    };
    let want: u32 = code.parse().unwrap_or(u32::MAX);
    let step = unix_time / 30;
    let mut ok = 0u8;
    for s in [step.saturating_sub(1), step, step + 1] {
        // Evaluate all windows to keep timing uniform.
        ok |= subtle::ConstantTimeEq::ct_eq(&hotp(&key, s), &want).unwrap_u8();
    }
    ok == 1
}

pub fn totp_uri(user: &str, secret: &str) -> String {
    format!("otpauth://totp/portvakt:{user}?secret={secret}&issuer=portvakt&algorithm=SHA1&digits=6&period=30")
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Session {
    pub user: String,
    pub role: Role,
    pub csrf: String,
    created: Instant,
    last_seen: Instant,
}

pub struct Auth {
    users: HashMap<String, User>,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
    dummy_hash: String,
    idle: Duration,
    absolute: Duration,
    max_failures: u32,
    lockout: Duration,
}

pub enum LoginError {
    /// Too many failures; retry later. Never reveals whether the account exists.
    RateLimited,
    Invalid,
    TotpRequired,
}

impl Auth {
    pub fn new(cfg: &Config) -> Result<Self> {
        Ok(Self {
            users: cfg.users.iter().map(|u| (u.name.clone(), u.clone())).collect(),
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            dummy_hash: hash_password(&random_token(16))?,
            idle: Duration::from_secs(cfg.security.session_idle_minutes * 60),
            absolute: Duration::from_secs(cfg.security.session_absolute_hours * 3600),
            max_failures: cfg.security.max_login_failures,
            lockout: Duration::from_secs(cfg.security.lockout_minutes * 60),
        })
    }

    fn limited(&self, keys: &[String]) -> bool {
        let mut f = self.failures.lock().unwrap();
        let now = Instant::now();
        keys.iter().any(|k| {
            let list = f.entry(k.clone()).or_default();
            list.retain(|t| now.duration_since(*t) < self.lockout);
            list.len() as u32 >= self.max_failures
        })
    }

    fn record_failure(&self, keys: &[String]) {
        let mut f = self.failures.lock().unwrap();
        for k in keys {
            f.entry(k.clone()).or_default().push(Instant::now());
        }
    }

    /// Returns (raw session token, session) on success.
    pub fn login(
        &self,
        ip: IpAddr,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> std::result::Result<(String, Session), LoginError> {
        // Limit per source IP and per account (slows distributed guessing on one account).
        let keys = [format!("ip:{ip}"), format!("user:{username}")];
        if self.limited(&keys) {
            return Err(LoginError::RateLimited);
        }
        let user = self.users.get(username);
        let hash = user.map(|u| u.password_hash.as_str()).unwrap_or(&self.dummy_hash);
        let pw_ok = verify_password(password, hash) && user.is_some();
        if !pw_ok {
            self.record_failure(&keys);
            return Err(LoginError::Invalid);
        }
        let user = user.unwrap();
        if let Some(secret) = &user.totp_secret {
            let Some(code) = totp.filter(|c| !c.is_empty()) else {
                // Password was right; don't count as failure, just ask for the code.
                return Err(LoginError::TotpRequired);
            };
            if !verify_totp(secret, code, unix_now()) {
                self.record_failure(&keys);
                return Err(LoginError::Invalid);
            }
        }
        self.failures.lock().unwrap().remove(&keys[1]);
        let token = random_token(32);
        let now = Instant::now();
        let session =
            Session { user: user.name.clone(), role: user.role, csrf: random_token(32), created: now, last_seen: now };
        self.sessions.lock().unwrap().insert(token_key(&token), session.clone());
        Ok((token, session))
    }

    /// Looks up and refreshes a session. Expired sessions are removed.
    pub fn session(&self, token: &str) -> Option<Session> {
        let key = token_key(token);
        let mut map = self.sessions.lock().unwrap();
        let now = Instant::now();
        let s = map.get_mut(&key)?;
        if now.duration_since(s.last_seen) > self.idle || now.duration_since(s.created) > self.absolute {
            map.remove(&key);
            return None;
        }
        s.last_seen = now;
        Some(s.clone())
    }

    /// Like `session` but does not count as activity (used by background checks).
    pub fn session_peek(&self, token: &str) -> Option<Session> {
        let map = self.sessions.lock().unwrap();
        let now = Instant::now();
        let s = map.get(&token_key(token))?;
        if now.duration_since(s.last_seen) > self.idle || now.duration_since(s.created) > self.absolute {
            return None;
        }
        Some(s.clone())
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(&token_key(token));
    }

    /// Drops expired sessions and stale failure records. Called periodically.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.sessions.lock().unwrap().retain(|_, s| {
            now.duration_since(s.last_seen) <= self.idle && now.duration_since(s.created) <= self.absolute
        });
        self.failures.lock().unwrap().retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < self.lockout);
            !v.is_empty()
        });
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("x", "garbage"));
    }

    #[test]
    fn totp_rfc6238_vector() {
        // RFC 6238 SHA-1 secret "12345678901234567890"; at T=59 the 8-digit code is 94287082.
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, b"12345678901234567890");
        assert!(verify_totp(&secret, "287082", 59));
        assert!(!verify_totp(&secret, "287083", 59));
        assert!(!verify_totp(&secret, "287082", 59 + 300));
    }

    #[test]
    fn usernames() {
        assert!(valid_username("admin"));
        assert!(valid_username("a.b-c_d"));
        assert!(!valid_username(""));
        assert!(!valid_username("a b"));
        assert!(!valid_username("a/b"));
    }

    #[test]
    fn rate_limit_and_sessions() {
        let mut cfg: Config = toml::from_str("[server]\n").unwrap();
        cfg.security.max_login_failures = 2;
        cfg.users.push(User {
            name: "admin".into(),
            password_hash: hash_password("pw").unwrap(),
            role: Role::Admin,
            totp_secret: None,
        });
        let auth = Auth::new(&cfg).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matches!(auth.login(ip, "admin", "bad", None), Err(LoginError::Invalid)));
        assert!(matches!(auth.login(ip, "admin", "bad", None), Err(LoginError::Invalid)));
        assert!(matches!(auth.login(ip, "admin", "pw", None), Err(LoginError::RateLimited)));

        let other: IpAddr = "10.0.0.2".parse().unwrap();
        // Account-level limit also applies from a new IP.
        assert!(matches!(auth.login(other, "admin", "pw", None), Err(LoginError::RateLimited)));

        let auth = Auth::new(&cfg).unwrap();
        let (token, s) = auth.login(ip, "admin", "pw", None).ok().unwrap();
        assert_eq!(s.role, Role::Admin);
        assert!(auth.session(&token).is_some());
        assert!(auth.session("nope").is_none());
        auth.logout(&token);
        assert!(auth.session(&token).is_none());
    }
}
