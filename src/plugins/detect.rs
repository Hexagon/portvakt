//! Detection engine: decides whether a plugin's application is installed.

use super::manifest::{DetectRule, Manifest};
use crate::exec;
use regex::Regex;
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

const DETECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, Serialize)]
pub struct Detection {
    pub detected: bool,
    /// Human-readable reasons, e.g. "binary /usr/sbin/nginx".
    pub evidence: Vec<String>,
    pub version: Option<String>,
}

const UNIT_DIRS: &[&str] =
    &["/etc/systemd/system", "/run/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"];

/// Returns evidence string if the rule matches.
pub async fn eval_rule(rule: &DetectRule) -> Option<String> {
    if let Some(b) = &rule.binary {
        return exec::resolve(b).map(|p| format!("binary {}", p.display()));
    }
    if let Some(p) = &rule.path {
        return first_glob_match(p).map(|m| format!("path {m}"));
    }
    if let Some(u) = &rule.systemd_unit {
        return UNIT_DIRS
            .iter()
            .map(|d| Path::new(d).join(u))
            .find(|p| p.exists())
            .map(|p| format!("unit {}", p.display()));
    }
    if let Some(name) = &rule.process {
        return process_running(name).then(|| format!("process {name}"));
    }
    if let Some(port) = rule.port {
        return port_listening(port).then(|| format!("listening on tcp/{port}"));
    }
    if let Some(cmd) = &rule.command {
        let argv = exec::prepare(cmd, false, false).ok()?;
        let out = exec::run(argv, DETECT_TIMEOUT).await;
        if !out.success() {
            return None;
        }
        if let Some(r) = &rule.regex {
            let re = Regex::new(r).ok()?;
            if !re.is_match(&out.combined()) {
                return None;
            }
        }
        return Some(format!("command {}", cmd.join(" ")));
    }
    None
}

pub async fn detect(m: &Manifest) -> Detection {
    let mut d = Detection::default();
    let mut any_ok = m.detect.any.is_empty();
    for r in &m.detect.any {
        if let Some(e) = eval_rule(r).await {
            d.evidence.push(e);
            any_ok = true;
        }
    }
    let mut all_ok = true;
    for r in &m.detect.all {
        match eval_rule(r).await {
            Some(e) => d.evidence.push(e),
            None => all_ok = false,
        }
    }
    d.detected = any_ok && all_ok;
    if d.detected
        && let Some(v) = &m.version
        && let Ok(argv) = exec::prepare(&v.command, false, false)
    {
        let out = exec::run(argv, DETECT_TIMEOUT).await;
        // Many tools print versions on stderr and some exit non-zero for --version.
        let text = format!("{}\n{}", out.stdout, out.stderr);
        if let Ok(re) = Regex::new(&v.regex) {
            d.version = re.captures(&text).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string());
        }
    }
    d
}

pub fn first_glob_match(pattern: &str) -> Option<String> {
    glob::glob(pattern).ok()?.flatten().next().map(|p| p.display().to_string())
}

fn process_running(name: &str) -> bool {
    let Ok(rd) = std::fs::read_dir("/proc") else { return false };
    rd.flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .any(|e| std::fs::read_to_string(e.path().join("comm")).map(|c| c.trim_end() == name).unwrap_or(false))
}

/// Parses /proc/net/tcp{,6} for sockets in LISTEN state (0A).
pub fn port_listening(port: u16) -> bool {
    let needle = format!(":{port:04X}");
    ["/proc/net/tcp", "/proc/net/tcp6"].iter().any(|f| {
        std::fs::read_to_string(f)
            .map(|text| {
                text.lines().skip(1).any(|l| {
                    let cols: Vec<&str> = l.split_whitespace().collect();
                    cols.len() > 3 && cols[1].ends_with(&needle) && cols[3] == "0A"
                })
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rules() {
        let r = DetectRule { binary: Some("sh".into()), ..Default::default() };
        assert!(eval_rule(&r).await.is_some());
        let r = DetectRule { path: Some("/proc/self/stat*".into()), ..Default::default() };
        assert!(eval_rule(&r).await.is_some());
        let r = DetectRule { path: Some("/nonexistent/x".into()), ..Default::default() };
        assert!(eval_rule(&r).await.is_none());
        let r = DetectRule {
            command: Some(vec!["echo".into(), "hello 1.2".into()]),
            regex: Some(r"hello \d".into()),
            ..Default::default()
        };
        assert!(eval_rule(&r).await.is_some());
    }

    #[tokio::test]
    async fn listening_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(port_listening(port));
    }
}
