//! Native (Rust) plugins.
//!
//! Prefer declarative TOML plugins. Write a native plugin only when you need data that
//! can't reasonably come from running a command (e.g. parsing /proc). A native plugin is
//! a TOML manifest (same rules as any plugin) plus Rust hooks. Register it in `all()`.

use super::manifest::Manifest;

pub trait NativePlugin: Send + Sync {
    /// Manifest TOML. Validated like any other plugin at startup.
    fn manifest(&self) -> &'static str;

    /// Extra key/value rows shown in the app overview. Runs on a blocking thread;
    /// must be fast (< 1 s) and must not run external programs (use `info` probes for that).
    fn info(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

pub fn all() -> Vec<Box<dyn NativePlugin>> {
    vec![Box::new(System)]
}

pub fn parse(p: &dyn NativePlugin) -> anyhow::Result<Manifest> {
    Manifest::parse(p.manifest())
}

/// Host overview: always detected.
pub struct System;

impl NativePlugin for System {
    fn manifest(&self) -> &'static str {
        include_str!("system.toml")
    }

    fn info(&self) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        rows.push(("Hostname".into(), read("/proc/sys/kernel/hostname").trim().to_string()));
        rows.push(("Kernel".into(), read("/proc/sys/kernel/osrelease").trim().to_string()));
        if let Some(name) = read("/etc/os-release")
            .lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .map(|s| s.trim_matches('"').to_string())
        {
            rows.push(("OS".into(), name));
        }
        if let Some(up) = read("/proc/uptime").split_whitespace().next().and_then(|s| s.parse::<f64>().ok()) {
            let s = up as u64;
            rows.push(("Uptime".into(), format!("{}d {}h {}m", s / 86400, s % 86400 / 3600, s % 3600 / 60)));
        }
        let load: Vec<String> = read("/proc/loadavg").split_whitespace().take(3).map(String::from).collect();
        if load.len() == 3 {
            rows.push(("Load (1/5/15 min)".into(), load.join(" / ")));
        }
        rows.push(("CPUs".into(), std::thread::available_parallelism().map(|n| n.to_string()).unwrap_or_default()));
        let mem = read("/proc/meminfo");
        let kb = |key: &str| {
            mem.lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        };
        if let (Some(total), Some(avail)) = (kb("MemTotal:"), kb("MemAvailable:")) {
            rows.push(("Memory".into(), format!("{} used of {}", human(total.saturating_sub(avail) * 1024), human(total * 1024))));
        }
        for mount in ["/", "/var", "/home", "/srv"] {
            if let Some((total, free)) = disk(mount) {
                if mount != "/" && !is_mountpoint(mount) {
                    continue;
                }
                rows.push((format!("Disk {mount}"), format!("{} free of {}", human(free), human(total))));
            }
        }
        rows
    }
}

fn is_mountpoint(p: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|m| m.lines().any(|l| l.split_whitespace().nth(1) == Some(p)))
        .unwrap_or(false)
}

fn disk(path: &str) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and a properly sized out-struct.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let f = st.f_frsize as u64;
    Some((st.f_blocks as u64 * f, st.f_bavail as u64 * f))
}

pub fn human(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_manifests_are_valid() {
        for p in all() {
            parse(p.as_ref()).unwrap();
        }
        assert!(!System.info().is_empty());
    }
}
