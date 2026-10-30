//! Server configuration (`portvakt.toml`).
//!
//! The config file contains password hashes and TOTP secrets, so it must not be
//! readable by other users. `Config::load` refuses files with unsafe permissions.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub terminal: TerminalConfig,
    #[serde(default)]
    pub plugins: PluginsConfig,
    #[serde(default)]
    pub users: Vec<User>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to listen on. Defaults to loopback only.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// PEM certificate chain. When set together with `tls_key`, HTTPS is served directly.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Set to true when a reverse proxy terminates TLS in front of portvakt.
    /// Enables trusting `X-Forwarded-For` from `trusted_proxies` and marks cookies `Secure`.
    #[serde(default)]
    pub behind_proxy: bool,
    #[serde(default)]
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// Exact public origin, e.g. `https://admin.example.com`. Strongly recommended when
    /// exposed to the internet; used for Origin checks on state-changing requests.
    pub public_origin: Option<String>,
    /// Directory for audit log and file backups.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Idle session timeout in minutes.
    #[serde(default = "default_idle")]
    pub session_idle_minutes: u64,
    /// Absolute session lifetime in hours.
    #[serde(default = "default_absolute")]
    pub session_absolute_hours: u64,
    /// Failed logins allowed per IP within `lockout_minutes` before blocking.
    #[serde(default = "default_max_failures")]
    pub max_login_failures: u32,
    #[serde(default = "default_lockout")]
    pub lockout_minutes: u64,
    /// Require TOTP for every admin account. Startup fails if an admin lacks a secret.
    #[serde(default)]
    pub require_totp_for_admins: bool,
    /// Prefix privileged plugin commands with `sudo -n --`. Lets portvakt run as an
    /// unprivileged user with a sudoers allow-list (see `portvakt sudoers`).
    #[serde(default)]
    pub use_sudo: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Shell to spawn. Must be an absolute path.
    #[serde(default = "default_shell")]
    pub shell: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginsConfig {
    /// Extra directories with `*.toml` plugin manifests. Must not be writable by others.
    #[serde(default)]
    pub dirs: Vec<PathBuf>,
    /// Plugin ids to disable (built-in or external).
    #[serde(default)]
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full access: actions, file editing, terminal.
    Admin,
    /// Read-only: can see detected apps and status.
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    pub role: Role,
    /// Base32 TOTP secret. When set, a code is required at login.
    pub totp_secret: Option<String>,
}

fn default_bind() -> SocketAddr {
    "127.0.0.1:8443".parse().unwrap()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/portvakt")
}
fn default_idle() -> u64 {
    30
}
fn default_absolute() -> u64 {
    12
}
fn default_max_failures() -> u32 {
    5
}
fn default_lockout() -> u64 {
    15
}
fn default_true() -> bool {
    true
}
fn default_shell() -> PathBuf {
    PathBuf::from("/bin/bash")
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_idle_minutes: default_idle(),
            session_absolute_hours: default_absolute(),
            max_login_failures: default_max_failures(),
            lockout_minutes: default_lockout(),
            require_totp_for_admins: false,
            use_sudo: false,
        }
    }
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self { enabled: true, shell: default_shell() }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        check_private_file(path)?;
        let text = std::fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self)?;
        write_private(path, text.as_bytes())
    }

    pub fn tls_enabled(&self) -> bool {
        self.server.tls_cert.is_some() && self.server.tls_key.is_some()
    }

    /// Cookies get `Secure` whenever the browser talks HTTPS to us or to our proxy.
    pub fn secure_cookies(&self) -> bool {
        self.tls_enabled() || self.server.behind_proxy
    }

    /// Hard safety rules. Startup is refused rather than running in an unsafe mode.
    pub fn validate(&self) -> Result<()> {
        let s = &self.server;
        if s.tls_cert.is_some() != s.tls_key.is_some() {
            bail!("server.tls_cert and server.tls_key must be set together");
        }
        if !s.bind.ip().is_loopback() && !self.tls_enabled() && !s.behind_proxy {
            bail!(
                "refusing to listen on {} without TLS. Set server.tls_cert/tls_key, \
                 or set server.behind_proxy = true if a TLS reverse proxy is in front",
                s.bind
            );
        }
        if s.behind_proxy && s.trusted_proxies.is_empty() {
            bail!("server.behind_proxy requires server.trusted_proxies");
        }
        if let Some(o) = &s.public_origin
            && (o.ends_with('/') || !(o.starts_with("https://") || o.starts_with("http://")))
        {
            bail!("server.public_origin must look like https://host[:port] (no trailing slash)");
        }
        if !self.terminal.shell.is_absolute() {
            bail!("terminal.shell must be an absolute path");
        }
        let mut names = std::collections::HashSet::new();
        for u in &self.users {
            if !crate::auth::valid_username(&u.name) {
                bail!("invalid username {:?}", u.name);
            }
            if !names.insert(&u.name) {
                bail!("duplicate user {:?}", u.name);
            }
            if self.security.require_totp_for_admins && u.role == Role::Admin && u.totp_secret.is_none() {
                bail!("user {:?} is admin but has no TOTP secret (require_totp_for_admins)", u.name);
            }
        }
        Ok(())
    }
}

/// Refuse config files that other users can read or write.
pub fn check_private_file(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o007 != 0 {
        bail!(
            "{} is accessible by other users (mode {:o}); run: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

/// Atomically write a 0600 file. When replacing an existing file, its owner is kept
/// (so `sudo portvakt user add` doesn't lock out a service running as another user).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let owner = std::fs::metadata(path).ok().map(|m| (m.uid(), m.gid()));
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        if let (Some((uid, gid)), true) = (owner, crate::exec::is_root()) {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        toml::from_str("[server]\n").unwrap()
    }

    #[test]
    fn loopback_without_tls_is_ok() {
        base().validate().unwrap();
    }

    #[test]
    fn public_bind_without_tls_is_refused() {
        let mut c = base();
        c.server.bind = "0.0.0.0:8443".parse().unwrap();
        assert!(c.validate().is_err());
        c.server.behind_proxy = true;
        assert!(c.validate().is_err(), "proxy mode needs trusted_proxies");
        c.server.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
        c.validate().unwrap();
    }
}
