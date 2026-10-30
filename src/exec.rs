//! The ONLY place where portvakt runs external programs on behalf of plugins.
//!
//! Rules enforced here:
//! - argv only, never a shell;
//! - the program is resolved against a fixed, root-owned PATH (not the caller's);
//! - environment is cleared except for a minimal safe set;
//! - stdin is closed, output is capped, a timeout kills the process.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_OUTPUT: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Output {
    pub argv: Vec<String>,
    /// None when killed by timeout or signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub millis: u64,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Find an executable by bare name in SAFE_PATH, or accept an absolute path.
pub fn resolve(program: &str) -> Option<PathBuf> {
    if program.starts_with('/') {
        return is_executable(Path::new(program)).then(|| PathBuf::from(program));
    }
    if program.contains('/') {
        return None;
    }
    SAFE_PATH.split(':').map(|d| Path::new(d).join(program)).find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// Build the final argv: resolved program, optional sudo prefix.
pub fn prepare(argv: &[String], privileged: bool, use_sudo: bool) -> Result<Vec<String>, String> {
    let (prog, rest) = argv.split_first().ok_or("empty command")?;
    let resolved = resolve(prog).ok_or_else(|| format!("program not found: {prog}"))?;
    let mut out = Vec::with_capacity(argv.len() + 3);
    if privileged && use_sudo && !is_root() {
        let sudo = resolve("sudo").ok_or("use_sudo is enabled but sudo is not installed")?;
        out.push(sudo.to_string_lossy().into_owned());
        out.push("-n".into());
        out.push("--".into());
    }
    out.push(resolved.to_string_lossy().into_owned());
    out.extend(rest.iter().cloned());
    Ok(out)
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub async fn run(argv: Vec<String>, timeout: Duration) -> Output {
    let start = Instant::now();
    let mut out = Output {
        argv: argv.clone(),
        code: None,
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
        millis: 0,
    };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("SYSTEMD_PAGER", "")
        .env("PAGER", "cat")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            out.stderr = format!("failed to start {}: {e}", argv[0]);
            return out;
        }
    };
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let work = async {
        let (a, b) = tokio::join!(read_capped(&mut so), read_capped(&mut se));
        let status = child.wait().await;
        (a, b, status)
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(((a, ta), (b, tb), status)) => {
            out.stdout = a;
            out.stderr = b;
            out.truncated = ta || tb;
            out.code = status.ok().and_then(|s| s.code());
        }
        Err(_) => {
            out.timed_out = true;
            out.stderr = format!("timed out after {}s", timeout.as_secs());
        }
    }
    out.millis = start.elapsed().as_millis() as u64;
    out
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (String, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < MAX_OUTPUT {
                    let take = n.min(MAX_OUTPUT - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                    truncated |= take < n;
                } else {
                    truncated = true; // keep draining so the child doesn't block
                }
            }
        }
    }
    (String::from_utf8_lossy(&buf).into_owned(), truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_without_shell() {
        let argv = prepare(&["echo".into(), "$HOME; rm -rf /".into()], false, false).unwrap();
        let o = run(argv, Duration::from_secs(5)).await;
        assert!(o.success());
        assert_eq!(o.stdout, "$HOME; rm -rf /\n");
    }

    #[tokio::test]
    async fn env_is_cleared() {
        // SAFETY: test-only, single env var.
        unsafe { std::env::set_var("PORTVAKT_SECRET_TEST", "leak") };
        let o = run(prepare(&["env".into()], false, false).unwrap(), Duration::from_secs(5)).await;
        assert!(!o.stdout.contains("leak"));
        assert!(o.stdout.contains(SAFE_PATH));
    }

    #[tokio::test]
    async fn timeout_kills() {
        let o = run(prepare(&["sleep".into(), "5".into()], false, false).unwrap(), Duration::from_millis(200)).await;
        assert!(o.timed_out);
        assert!(!o.success());
    }

    #[test]
    fn resolve_rules() {
        assert!(resolve("sh").is_some());
        assert!(resolve("./sh").is_none());
        assert!(resolve("definitely-not-a-program-xyz").is_none());
    }
}
