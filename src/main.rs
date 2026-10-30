mod audit;
mod auth;
mod config;
mod exec;
mod plugins;
mod terminal;
mod web;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::{Config, Role, User};
use std::io::{BufRead, IsTerminal};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "portvakt", version, about = "Secure, plugin-driven web admin for servers")]
struct Cli {
    /// Config file.
    #[arg(short, long, global = true, env = "PORTVAKT_CONFIG", default_value = "/etc/portvakt/portvakt.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the web server.
    Serve,
    /// Create a new config file with an admin user.
    Init {
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: SocketAddr,
        /// Generate a self-signed TLS certificate next to the config (for direct internet exposure).
        #[arg(long)]
        self_signed: bool,
        /// Hostnames/IPs for the self-signed certificate.
        #[arg(long = "san", default_values_t = ["localhost".to_string()])]
        sans: Vec<String>,
        #[arg(long)]
        public_origin: Option<String>,
        #[arg(long, default_value = "/var/lib/portvakt")]
        data_dir: PathBuf,
        #[arg(long, default_value = "admin")]
        admin: String,
        /// Read the admin password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Also set up TOTP for the admin and print the otpauth:// URI.
        #[arg(long)]
        totp: bool,
    },
    /// Manage users (restart portvakt afterwards to apply).
    #[command(subcommand)]
    User(UserCmd),
    /// Plugin development and inspection.
    #[command(subcommand)]
    Plugin(PluginCmd),
    /// Print a sudoers allow-list for all privileged commands of detected plugins.
    Sudoers {
        /// System user portvakt runs as.
        #[arg(long, default_value = "portvakt")]
        user: String,
        /// Include plugins that are not detected on this host.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    List,
    Add {
        name: String,
        #[arg(long, value_parser = ["admin", "viewer"], default_value = "admin")]
        role: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        totp: bool,
    },
    Passwd {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Enable or rotate TOTP for a user.
    Totp { name: String },
    /// Disable TOTP for a user.
    NoTotp { name: String },
    Remove { name: String },
}

#[derive(Subcommand)]
enum PluginCmd {
    /// Validate plugin manifest files. Exit code 1 on any error.
    Validate {
        files: Vec<PathBuf>,
        /// Also run detection and print the result.
        #[arg(long)]
        detect: bool,
    },
    /// List all plugins and whether they are detected here (uses config's plugin dirs if readable).
    List,
    /// Show what a plugin would expose on this host.
    Show { id: String },
    /// Probe this host for a program and print a starter manifest (TOML) to stdout.
    New {
        /// Program / binary name, e.g. "redis-server".
        program: String,
        /// Plugin id (defaults to the program name).
        #[arg(long)]
        id: Option<String>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::Serve => rt.block_on(serve(&cli.config)),
        Cmd::Init { bind, self_signed, sans, public_origin, data_dir, admin, password_stdin, totp } => {
            init(&cli.config, bind, self_signed, sans, public_origin, data_dir, &admin, password_stdin, totp)
        }
        Cmd::User(c) => user_cmd(&cli.config, c),
        Cmd::Plugin(c) => rt.block_on(plugin_cmd(&cli.config, c)),
        Cmd::Sudoers { user, all } => rt.block_on(sudoers(&cli.config, &user, all)),
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

async fn serve(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    if cfg.users.is_empty() {
        bail!("no users configured; run `portvakt user add <name>`");
    }
    std::fs::create_dir_all(&cfg.server.data_dir)
        .with_context(|| format!("creating data dir {}", cfg.server.data_dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg.server.data_dir, std::fs::Permissions::from_mode(0o700))?;

    let (plugins, plugin_errors) = plugins::load_all(&cfg.plugins.dirs, &cfg.plugins.disabled)?;
    for e in &plugin_errors {
        tracing::warn!("plugin skipped: {e}");
    }
    let registry = plugins::Registry::new(plugins);
    registry.rescan().await;
    tracing::info!("{} plugins loaded", registry.plugins.len());
    if exec::is_root() {
        tracing::warn!("running as root: the web terminal is a root shell. See docs/SECURITY.md for the sudo setup.");
    }

    let state = Arc::new(web::AppState {
        auth: auth::Auth::new(&cfg)?,
        audit: audit::Audit::new(cfg.server.data_dir.join("audit.log")),
        backup_dir: cfg.server.data_dir.join("backups"),
        pol: plugins::runtime::ExecPolicy { use_sudo: cfg.security.use_sudo },
        terminals: Default::default(),
        registry,
        plugin_errors,
        cfg,
    });

    let bg = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut n = 0u64;
        loop {
            tick.tick().await;
            bg.auth.sweep();
            n += 1;
            if n.is_multiple_of(10) {
                bg.registry.rescan().await;
            }
        }
    });

    let app = web::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let addr = state.cfg.server.bind;
    if let (Some(cert), Some(key)) = (&state.cfg.server.tls_cert, &state.cfg.server.tls_key) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .context("loading TLS certificate/key")?;
        tracing::info!("listening on https://{addr}");
        axum_server::bind_rustls(addr, tls).serve(app).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("listening on http://{addr}");
        axum::serve(listener, app).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// init / users
// ---------------------------------------------------------------------------

fn read_password(from_stdin: bool) -> Result<String> {
    let pw = if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\n', '\r']).to_string()
    } else {
        let a = rpassword::prompt_password("Password: ")?;
        let b = rpassword::prompt_password("Repeat password: ")?;
        if a != b {
            bail!("passwords do not match");
        }
        a
    };
    if pw.chars().count() < 12 {
        bail!("password must be at least 12 characters");
    }
    Ok(pw)
}

#[allow(clippy::too_many_arguments)]
fn init(
    path: &Path,
    bind: SocketAddr,
    self_signed: bool,
    sans: Vec<String>,
    public_origin: Option<String>,
    data_dir: PathBuf,
    admin: &str,
    password_stdin: bool,
    totp: bool,
) -> Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut cfg: Config = toml::from_str("[server]\n")?;
    cfg.server.bind = bind;
    cfg.server.data_dir = data_dir;
    cfg.server.public_origin = public_origin;
    if self_signed {
        let ck = rcgen::generate_simple_self_signed(sans).context("generating certificate")?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        config::write_private(&cert, ck.cert.pem().as_bytes())?;
        config::write_private(&key, ck.signing_key.serialize_pem().as_bytes())?;
        cfg.server.tls_cert = Some(cert);
        cfg.server.tls_key = Some(key);
    }
    if !auth::valid_username(admin) {
        bail!("invalid username");
    }
    let pw = read_password(password_stdin)?;
    let secret = totp.then(auth::generate_totp_secret);
    cfg.users.push(User { name: admin.into(), password_hash: auth::hash_password(&pw)?, role: Role::Admin, totp_secret: secret.clone() });
    cfg.validate()?;
    cfg.save(path)?;
    println!("Wrote {}", path.display());
    if let Some(s) = secret {
        println!("TOTP: add this to your authenticator app:\n  {}", auth::totp_uri(admin, &s));
    }
    Ok(())
}

fn user_cmd(path: &Path, c: UserCmd) -> Result<()> {
    let mut cfg = Config::load(path)?;
    let find = |cfg: &mut Config, n: &str| -> Result<usize> {
        cfg.users.iter().position(|u| u.name == n).with_context(|| format!("no user {n:?}"))
    };
    match c {
        UserCmd::List => {
            for u in &cfg.users {
                println!("{:<24} {:<7} totp={}", u.name, format!("{:?}", u.role).to_lowercase(), u.totp_secret.is_some());
            }
            return Ok(());
        }
        UserCmd::Add { name, role, password_stdin, totp } => {
            if cfg.users.iter().any(|u| u.name == name) {
                bail!("user exists");
            }
            let role = if role == "admin" { Role::Admin } else { Role::Viewer };
            let pw = read_password(password_stdin)?;
            let secret = totp.then(auth::generate_totp_secret);
            if let Some(s) = &secret {
                println!("TOTP URI: {}", auth::totp_uri(&name, s));
            }
            cfg.users.push(User { name, password_hash: auth::hash_password(&pw)?, role, totp_secret: secret });
        }
        UserCmd::Passwd { name, password_stdin } => {
            let i = find(&mut cfg, &name)?;
            cfg.users[i].password_hash = auth::hash_password(&read_password(password_stdin)?)?;
        }
        UserCmd::Totp { name } => {
            let i = find(&mut cfg, &name)?;
            let s = auth::generate_totp_secret();
            println!("TOTP URI: {}", auth::totp_uri(&name, &s));
            cfg.users[i].totp_secret = Some(s);
        }
        UserCmd::NoTotp { name } => {
            let i = find(&mut cfg, &name)?;
            cfg.users[i].totp_secret = None;
        }
        UserCmd::Remove { name } => {
            let i = find(&mut cfg, &name)?;
            cfg.users.remove(i);
        }
    }
    cfg.validate()?;
    cfg.save(path)?;
    println!("Saved. Restart portvakt to apply (systemctl restart portvakt).");
    Ok(())
}

// ---------------------------------------------------------------------------
// plugin tooling
// ---------------------------------------------------------------------------

fn plugin_dirs(path: &Path) -> (Vec<PathBuf>, Vec<String>) {
    match Config::load(path) {
        Ok(c) => (c.plugins.dirs, c.plugins.disabled),
        Err(_) => (vec![], vec![]),
    }
}

async fn plugin_cmd(path: &Path, c: PluginCmd) -> Result<()> {
    match c {
        PluginCmd::Validate { files, detect } => {
            let mut failed = false;
            for f in &files {
                let res = std::fs::read_to_string(f).map_err(anyhow::Error::from).and_then(|t| plugins::manifest::Manifest::parse(&t));
                match res {
                    Ok(m) => {
                        let stem = f.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                        if stem != m.id {
                            println!("FAIL {}: file name must be {}.toml", f.display(), m.id);
                            failed = true;
                            continue;
                        }
                        println!("ok   {} ({})", f.display(), m.id);
                        if detect {
                            let d = plugins::detect::detect(&m).await;
                            println!("     detected={} version={:?} evidence={:?}", d.detected, d.version, d.evidence);
                        }
                    }
                    Err(e) => {
                        println!("FAIL {}: {e:#}", f.display());
                        failed = true;
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
        PluginCmd::List => {
            let (dirs, disabled) = plugin_dirs(path);
            let (list, errors) = plugins::load_all(&dirs, &disabled)?;
            for e in errors {
                eprintln!("error: {e}");
            }
            for p in list {
                let d = plugins::detect::detect(&p.manifest).await;
                println!(
                    "{:<3} {:<16} {:<14} {}",
                    if d.detected { "✔" } else { "·" },
                    p.manifest.id,
                    d.version.unwrap_or_default(),
                    p.manifest.name
                );
            }
        }
        PluginCmd::New { program, id } => scaffold(&program, id).await?,
        PluginCmd::Show { id } => {
            let (dirs, disabled) = plugin_dirs(path);
            let (list, _) = plugins::load_all(&dirs, &disabled)?;
            let p = list.into_iter().find(|p| p.manifest.id == id).context("no such plugin")?;
            let d = plugins::detect::detect(&p.manifest).await;
            println!("{} ({}) detected={} version={:?}", p.manifest.name, id, d.detected, d.version);
            for e in d.evidence {
                println!("  evidence: {e}");
            }
            for a in plugins::runtime::actions(&p.manifest) {
                println!("  action {:<20} {}{}", a.id, a.label, if a.available { "" } else { " (program missing)" });
            }
            for f in plugins::runtime::files(&p.manifest) {
                println!("  file   {}{}", f.path, if f.readonly { " (read-only)" } else { "" });
            }
            for l in plugins::runtime::logs(&p.manifest) {
                println!("  log    {} — {}", l.label, l.source);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// plugin scaffolding
// ---------------------------------------------------------------------------

/// Generates a starting point from what is actually on this host. The output is a draft:
/// the author must review it (see docs/PLUGINS.md) and run `portvakt plugin validate`.
async fn scaffold(program: &str, id: Option<String>) -> Result<()> {
    if program.is_empty() || !program.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        bail!("program must be a bare name like `redis-server`");
    }
    let id = id.unwrap_or_else(|| program.to_lowercase().replace(['.', '_'], "-"));
    let base = program.trim_end_matches("-server").trim_end_matches('d');
    let names: Vec<String> = {
        let mut v = vec![program.to_string(), base.to_string(), id.clone()];
        v.dedup();
        v
    };
    let q = |s: &str| format!("{s:?}");
    let mut detect = Vec::new();
    let bin = exec::resolve(program);
    if bin.is_some() {
        detect.push(format!("{{ binary = {} }}", q(program)));
    }
    let unit = names.iter().map(|n| format!("{n}.service")).find(|u| {
        ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"].iter().any(|d| Path::new(d).join(u).exists())
    });
    if let Some(u) = &unit {
        detect.push(format!("{{ systemd_unit = {} }}", q(u)));
    }
    let mut conf_files = Vec::new();
    for n in &names {
        for pat in [format!("/etc/{n}/{n}.conf"), format!("/etc/{n}.conf"), format!("/etc/{n}/*.conf"), format!("/etc/{n}/conf.d/*.conf"), format!("/etc/{n}/*.yaml"), format!("/etc/{n}/*.yml"), format!("/etc/{n}/*.toml"), format!("/etc/{n}/*.json")] {
            if plugins::detect::first_glob_match(&pat).is_some() && !conf_files.contains(&pat) {
                conf_files.push(pat);
            }
        }
        let dir = format!("/etc/{n}");
        if Path::new(&dir).is_dir() && !detect.iter().any(|d| d.contains(&dir)) {
            detect.push(format!("{{ path = {} }}", q(&dir)));
        }
    }
    let mut version = None;
    if bin.is_some() {
        let re = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?[\w.+-]*)").unwrap();
        for flag in ["--version", "-v", "-V", "version"] {
            let argv = exec::prepare(&[program.to_string(), flag.to_string()], false, false).map_err(anyhow::Error::msg)?;
            let out = exec::run(argv, std::time::Duration::from_secs(3)).await;
            let text = out.combined();
            if let Some(m) = re.find(&text) {
                let line = text.lines().find(|l| l.contains(m.as_str())).unwrap_or("");
                version = Some((flag, line.trim().to_string()));
                break;
            }
        }
    }
    let logs: Vec<String> = names
        .iter()
        .flat_map(|n| [format!("/var/log/{n}/*.log"), format!("/var/log/{n}.log")])
        .filter(|p| plugins::detect::first_glob_match(p).is_some())
        .collect();

    if detect.is_empty() {
        bail!("nothing found for {program:?} on this host (no binary, unit or /etc dir). Install it first or write the manifest by hand.");
    }
    println!("# Draft generated by `portvakt plugin new {program}`. REVIEW EVERYTHING (docs/PLUGINS.md),");
    println!("# then: portvakt plugin validate --detect {id}.toml");
    println!("id = {}\nname = {}\ndescription = \"TODO: one line about what {program} is.\"", q(&id), q(program));
    println!("category = \"TODO\"  # e.g. Web servers, Databases, Containers, Security, Monitoring\nicon = \"app\"\n");
    println!("[detect]\nany = [{}]\n", detect.join(", "));
    if let Some((flag, line)) = version {
        println!("# `{program} {flag}` printed: {line}");
        println!("[version]\ncommand = [{}, {}]\nregex = '(\\d+\\.\\d+(?:\\.\\d+)?)'  # TODO: tighten, e.g. '{program} v(\\S+)'\n", q(program), q(flag));
    }
    if let Some(u) = &unit {
        println!("[service]\nsystemd = {}\nactions = [\"start\", \"stop\", \"restart\"]  # add \"reload\" if the unit supports it\n", q(u));
    }
    for f in &conf_files {
        println!("[[files]]\npath = {}\n# validate = [{}, \"TODO-config-test-flag\"]  # strongly recommended\n# validate_privileged = true\n# after_save = \"restart\"\n", q(f), q(program));
    }
    for l in &logs {
        println!("[[logs]]\nlabel = \"Log\"\npath = {}\n", q(l));
    }
    if let Some(u) = &unit {
        println!("[[logs]]\nlabel = \"Journal\"\njournal = {}\n", q(u));
    }
    println!("# TODO: [[actions]] for the program's own maintenance commands (argv only, no shell).");
    Ok(())
}

// ---------------------------------------------------------------------------
// sudoers generator
// ---------------------------------------------------------------------------

fn sudoers_escape(arg: &str) -> String {
    arg.chars()
        .flat_map(|c| if ",:=\\ ".contains(c) { vec!['\\', c] } else { vec![c] })
        .collect()
}

async fn sudoers(path: &Path, user: &str, all: bool) -> Result<()> {
    if !auth::valid_username(user) {
        bail!("invalid user");
    }
    let (dirs, disabled) = plugin_dirs(path);
    let (list, _) = plugins::load_all(&dirs, &disabled)?;
    println!("# Generated by `portvakt sudoers`. Install with: visudo -f /etc/sudoers.d/portvakt");
    println!("# Review every line. Lines with '*' accept arbitrary arguments in that position.");
    println!("Defaults:{user} !requiretty");
    let re = regex::Regex::new(r"\{[a-z_][a-z0-9_]*\}").unwrap();
    for p in list {
        let m = &p.manifest;
        if !all && !plugins::detect::detect(m).await.detected {
            continue;
        }
        let mut cmds: Vec<(Vec<String>, bool)> = Vec::new();
        for id in m.action_ids() {
            let a = plugins::runtime::find_action(m, &id).unwrap();
            if a.privileged {
                cmds.push((a.command.clone(), !a.params.is_empty()));
            }
        }
        for f in &m.files {
            if let (Some(v), true) = (&f.validate, f.validate_privileged) {
                cmds.push((v.clone(), !plugins::manifest::placeholders(v).is_empty()));
            }
        }
        for i in &m.info {
            if i.privileged {
                cmds.push((i.command.clone(), false));
            }
        }
        for l in &m.logs {
            if let Some(u) = &l.journal {
                cmds.push((["journalctl", "-u", u, "-n", "500", "--no-pager", "-o", "short-iso"].map(String::from).to_vec(), false));
            }
        }
        if cmds.is_empty() {
            continue;
        }
        println!("\n# {} ({})", m.name, m.id);
        for (argv, wild) in cmds {
            let Some(prog) = exec::resolve(&argv[0]) else {
                println!("# skipped (not installed): {}", argv.join(" "));
                continue;
            };
            let args: Vec<String> =
                argv[1..].iter().map(|a| if re.is_match(a) { "*".to_string() } else { sudoers_escape(a) }).collect();
            if wild {
                println!("# NOTE: wildcard below; values are validated by portvakt but sudo itself will accept any.");
            }
            // In sudoers a command without arguments allows ANY arguments; "" means none.
            let args = if args.is_empty() { "\"\"".to_string() } else { args.join(" ") };
            println!("{user} ALL=(root) NOPASSWD: {} {args}", prog.display());
        }
    }
    Ok(())
}
