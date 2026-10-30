//! Append-only audit log (JSON lines) of every security-relevant event.

use serde::Serialize;
use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

const KEEP_IN_MEMORY: usize = 500;

#[derive(Clone, Serialize)]
pub struct Entry {
    pub time: u64,
    pub user: String,
    pub ip: String,
    pub event: String,
    pub detail: String,
    pub ok: bool,
}

pub struct Audit {
    path: PathBuf,
    recent: Mutex<VecDeque<Entry>>,
}

impl Audit {
    pub fn new(path: PathBuf) -> Self {
        Self { path, recent: Mutex::new(VecDeque::new()) }
    }

    pub fn log(&self, user: &str, ip: impl ToString, event: &str, detail: impl Into<String>, ok: bool) {
        let e = Entry {
            time: crate::auth::unix_now(),
            user: user.to_string(),
            ip: ip.to_string(),
            event: event.to_string(),
            detail: detail.into(),
            ok,
        };
        tracing::info!(target: "audit", user = %e.user, ip = %e.ip, event = %e.event, ok = e.ok, "{}", e.detail);
        let line = serde_json::to_string(&e).unwrap_or_default();
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(err) = res {
            tracing::error!("audit log write failed ({}): {err}", self.path.display());
        }
        let mut r = self.recent.lock().unwrap();
        r.push_back(e);
        while r.len() > KEEP_IN_MEMORY {
            r.pop_front();
        }
    }

    pub fn recent(&self) -> Vec<Entry> {
        self.recent.lock().unwrap().iter().rev().cloned().collect()
    }
}
