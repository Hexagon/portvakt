//! Native (Rust) plugins.
//!
//! Prefer declarative TOML plugins. Write a native plugin only when you need data that
//! can't reasonably come from running a command (e.g. parsing /proc, sending signals,
//! sampling metrics over time). A native plugin is a TOML manifest (same rules as any
//! plugin; it may declare views without `command`) plus Rust hooks. Register it in `all()`.

use super::manifest::Manifest;
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub trait NativePlugin: Send + Sync {
    /// Manifest TOML. Validated like any other plugin at startup.
    fn manifest(&self) -> &'static str;

    /// Extra key/value rows shown in the app overview. Runs on a blocking thread;
    /// must be fast (< 1 s).
    fn info(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Data for a view declared in the manifest without `command`.
    /// Table: `{"rows": [...]}`. Metrics: `{"series": [{id,label,unit,max,points:[[t,v]]}]}`.
    fn view_data(&self, view: &str) -> Result<Value> {
        bail!("view {view:?} has no data provider")
    }

    /// Row action on a native table view. `row` is the row object as sent to the UI;
    /// re-validate everything in it. Returns a human-readable result message.
    fn view_action(&self, view: &str, action: &str, _row: &Value) -> Result<String> {
        bail!("unknown action {action:?} for view {view:?}")
    }
}

pub fn all() -> Vec<Box<dyn NativePlugin>> {
    vec![Box::new(System), Box::new(Processes::default()), Box::new(Monitor), Box::new(Terminal)]
}

pub fn parse(p: &dyn NativePlugin) -> Result<Manifest> {
    Manifest::parse(p.manifest())
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn meminfo_kb(mem: &str, key: &str) -> Option<u64> {
    mem.lines().find_map(|l| l.strip_prefix(key)).and_then(|r| r.split_whitespace().next()).and_then(|n| n.parse().ok())
}

// ---------------------------------------------------------------------------
// System overview
// ---------------------------------------------------------------------------

/// Host overview: always detected.
pub struct System;

impl NativePlugin for System {
    fn manifest(&self) -> &'static str {
        include_str!("native/system.toml")
    }

    fn info(&self) -> Vec<(String, String)> {
        let mut rows = Vec::new();
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
        if let (Some(total), Some(avail)) = (meminfo_kb(&mem, "MemTotal:"), meminfo_kb(&mem, "MemAvailable:")) {
            rows.push((
                "Memory".into(),
                format!("{} used of {}", human(total.saturating_sub(avail) * 1024), human(total * 1024)),
            ));
        }
        for mount in ["/", "/var", "/home", "/srv"] {
            if mount != "/" && !is_mountpoint(mount) {
                continue;
            }
            if let Some((total, free)) = disk(mount) {
                rows.push((format!("Disk {mount}"), format!("{} free of {}", human(free), human(total))));
            }
        }
        rows
    }
}

fn is_mountpoint(p: &str) -> bool {
    read("/proc/mounts").lines().any(|l| l.split_whitespace().nth(1) == Some(p))
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

// ---------------------------------------------------------------------------
// Task manager: processes from /proc, works on any Linux distro
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Processes {
    /// pid → (cpu ticks, sampled at). Used for CPU% between refreshes.
    last: Mutex<HashMap<i32, (u64, Instant)>>,
}

struct ProcStat {
    state: String,
    ticks: u64,
    start: u64,
    rss_pages: u64,
    threads: u64,
}

fn proc_stat(pid: i32) -> Option<ProcStat> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces/parens: split after the LAST ')'.
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // f[0] = field 3 (state); utime=14, stime=15, threads=20, starttime=22, rss=24.
    let n = |i: usize| f.get(i - 3).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    Some(ProcStat {
        state: f.first()?.to_string(),
        ticks: n(14) + n(15),
        start: n(22),
        rss_pages: n(24),
        threads: n(20),
    })
}

fn users() -> HashMap<u32, String> {
    read("/etc/passwd")
        .lines()
        .filter_map(|l| {
            let mut it = l.split(':');
            let name = it.next()?;
            let uid = it.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

fn clk_tck() -> f64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as f64 } else { 100.0 }
}

fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as u64 } else { 4096 }
}

impl NativePlugin for Processes {
    fn manifest(&self) -> &'static str {
        include_str!("native/processes.toml")
    }

    fn view_data(&self, view: &str) -> Result<Value> {
        if view != "processes" {
            bail!("unknown view");
        }
        let users = users();
        let tck = clk_tck();
        let page = page_size();
        let mem_total = meminfo_kb(&read("/proc/meminfo"), "MemTotal:").unwrap_or(1) * 1024;
        let uptime: f64 = read("/proc/uptime").split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let now = Instant::now();
        let mut last = self.last.lock().unwrap();
        let mut next = HashMap::new();
        let mut rows = Vec::new();
        for e in std::fs::read_dir("/proc")?.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            let Some(st) = proc_stat(pid) else { continue };
            let uid = read(&format!("/proc/{pid}/status"))
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|u| u.parse::<u32>().ok())
                .unwrap_or(0);
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let mut cmd = String::from_utf8_lossy(&cmdline).replace('\0', " ").trim().to_string();
            let comm = read(&format!("/proc/{pid}/comm")).trim().to_string();
            if cmd.is_empty() {
                cmd = format!("[{comm}]");
            }
            let cpu = match last.get(&pid) {
                Some((t, at)) if st.ticks >= *t => {
                    let dt = now.duration_since(*at).as_secs_f64().max(0.001);
                    (st.ticks - t) as f64 / tck / dt * 100.0
                }
                _ => {
                    // First sample: average over the process lifetime.
                    let age = (uptime - st.start as f64 / tck).max(0.001);
                    st.ticks as f64 / tck / age * 100.0
                }
            };
            next.insert(pid, (st.ticks, now));
            let rss = st.rss_pages * page;
            rows.push(json!({
                "pid": pid, "user": users.get(&uid).cloned().unwrap_or_else(|| uid.to_string()),
                "name": comm, "state": st.state, "cpu": (cpu * 10.0).round() / 10.0,
                "mem": ((rss as f64 / mem_total as f64) * 1000.0).round() / 10.0, "rss": rss,
                "threads": st.threads, "start": st.start, "command": cmd.chars().take(300).collect::<String>(),
            }));
        }
        *last = next;
        rows.sort_by(|a, b| {
            let k = |v: &Value| (v["cpu"].as_f64().unwrap_or(0.0), v["mem"].as_f64().unwrap_or(0.0));
            k(b).partial_cmp(&k(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(json!({ "rows": rows }))
    }

    fn view_action(&self, view: &str, action: &str, row: &Value) -> Result<String> {
        if view != "processes" {
            bail!("unknown view");
        }
        let signal = match action {
            "terminate" => libc::SIGTERM,
            "kill" => libc::SIGKILL,
            _ => bail!("unknown action"),
        };
        let pid =
            row["pid"].as_i64().filter(|p| *p > 1 && *p < i32::MAX as i64).ok_or_else(|| anyhow!("invalid pid"))?
                as i32;
        if pid == std::process::id() as i32 {
            bail!("refusing to signal portvakt itself");
        }
        // Guard against PID reuse: the process must still have the same start time.
        let start = row["start"].as_u64().ok_or_else(|| anyhow!("missing start time"))?;
        let st = proc_stat(pid).ok_or_else(|| anyhow!("process {pid} no longer exists"))?;
        if st.start != start {
            bail!("pid {pid} now belongs to a different process; refresh the list");
        }
        // SAFETY: plain syscall with validated arguments.
        if unsafe { libc::kill(pid, signal) } != 0 {
            bail!("kill({pid}) failed: {}", std::io::Error::last_os_error());
        }
        Ok(format!("sent {} to {pid}", if signal == libc::SIGKILL { "SIGKILL" } else { "SIGTERM" }))
    }
}

// ---------------------------------------------------------------------------
// System monitor: background sampler with 10 minutes of history
// ---------------------------------------------------------------------------

pub struct Monitor;

const SAMPLE_EVERY: Duration = Duration::from_secs(2);
const HISTORY: usize = 300;

struct Series {
    id: &'static str,
    label: &'static str,
    unit: &'static str,
    max: Option<f64>,
    points: VecDeque<(u64, f64)>,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    cpu_total: u64,
    cpu_idle: u64,
    net_rx: u64,
    net_tx: u64,
    disk_read: u64,
    disk_write: u64,
}

fn counters() -> Counters {
    let mut c = Counters::default();
    if let Some(l) = read("/proc/stat").lines().next() {
        let v: Vec<u64> = l.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
        c.cpu_total = v.iter().take(8).sum();
        c.cpu_idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    }
    for l in read("/proc/net/dev").lines().skip(2) {
        let Some((iface, rest)) = l.split_once(':') else { continue };
        if iface.trim() == "lo" {
            continue;
        }
        let v: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        c.net_rx += v.first().copied().unwrap_or(0);
        c.net_tx += v.get(8).copied().unwrap_or(0);
    }
    for l in read("/proc/diskstats").lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let name = f[2];
        // Whole disks only (partitions would double count).
        if name.starts_with("loop")
            || name.starts_with("ram")
            || !std::path::Path::new(&format!("/sys/block/{name}")).exists()
        {
            continue;
        }
        c.disk_read += f[5].parse::<u64>().unwrap_or(0) * 512;
        c.disk_write += f[9].parse::<u64>().unwrap_or(0) * 512;
    }
    c
}

fn history() -> &'static Mutex<Vec<Series>> {
    static H: OnceLock<Mutex<Vec<Series>>> = OnceLock::new();
    H.get_or_init(|| {
        let s = |id, label, unit, max| Series { id, label, unit, max, points: VecDeque::new() };
        let h = Mutex::new(vec![
            s("cpu", "CPU", "%", Some(100.0)),
            s("mem", "Memory", "%", Some(100.0)),
            s("swap", "Swap", "%", Some(100.0)),
            s("load", "Load (1 min)", "", None),
            s("net_rx", "Network in", "B/s", None),
            s("net_tx", "Network out", "B/s", None),
            s("disk_read", "Disk read", "B/s", None),
            s("disk_write", "Disk write", "B/s", None),
        ]);
        std::thread::spawn(sampler);
        h
    })
}

fn sampler() {
    let mut prev = counters();
    let mut prev_t = Instant::now();
    loop {
        std::thread::sleep(SAMPLE_EVERY);
        let cur = counters();
        let dt = prev_t.elapsed().as_secs_f64().max(0.001);
        prev_t = Instant::now();
        let mem = read("/proc/meminfo");
        let pct = |used: u64, total: u64| if total == 0 { 0.0 } else { used as f64 / total as f64 * 100.0 };
        let mt = meminfo_kb(&mem, "MemTotal:").unwrap_or(0);
        let ma = meminfo_kb(&mem, "MemAvailable:").unwrap_or(0);
        let st = meminfo_kb(&mem, "SwapTotal:").unwrap_or(0);
        let sf = meminfo_kb(&mem, "SwapFree:").unwrap_or(0);
        let dtot = cur.cpu_total.saturating_sub(prev.cpu_total);
        let didle = cur.cpu_idle.saturating_sub(prev.cpu_idle);
        let rate = |a: u64, b: u64| a.saturating_sub(b) as f64 / dt;
        let values = [
            ("cpu", pct(dtot.saturating_sub(didle), dtot)),
            ("mem", pct(mt.saturating_sub(ma), mt)),
            ("swap", pct(st.saturating_sub(sf), st)),
            ("load", read("/proc/loadavg").split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0)),
            ("net_rx", rate(cur.net_rx, prev.net_rx)),
            ("net_tx", rate(cur.net_tx, prev.net_tx)),
            ("disk_read", rate(cur.disk_read, prev.disk_read)),
            ("disk_write", rate(cur.disk_write, prev.disk_write)),
        ];
        prev = cur;
        let t = crate::auth::unix_now();
        let mut h = history().lock().unwrap();
        for (id, v) in values {
            if let Some(s) = h.iter_mut().find(|s| s.id == id) {
                s.points.push_back((t, (v * 10.0).round() / 10.0));
                while s.points.len() > HISTORY {
                    s.points.pop_front();
                }
            }
        }
    }
}

impl NativePlugin for Monitor {
    fn manifest(&self) -> &'static str {
        include_str!("native/monitor.toml")
    }

    fn view_data(&self, view: &str) -> Result<Value> {
        if view != "monitor" {
            bail!("unknown view");
        }
        let h = history().lock().unwrap();
        let series: Vec<Value> = h
            .iter()
            .map(|s| json!({ "id": s.id, "label": s.label, "unit": s.unit, "max": s.max, "points": s.points.iter().map(|(t, v)| json!([t, v])).collect::<Vec<_>>() }))
            .collect();
        Ok(json!({ "series": series, "interval": SAMPLE_EVERY.as_secs() }))
    }
}

// ---------------------------------------------------------------------------
// Terminal: the PTY lives in terminal.rs; this plugin makes it discoverable/disableable.
// ---------------------------------------------------------------------------

pub struct Terminal;

impl NativePlugin for Terminal {
    fn manifest(&self) -> &'static str {
        include_str!("native/terminal.toml")
    }
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

    #[test]
    fn processes_list_and_guard() {
        let p = Processes::default();
        let data = p.view_data("processes").unwrap();
        let rows = data["rows"].as_array().unwrap();
        let me = std::process::id() as i64;
        let row = rows.iter().find(|r| r["pid"].as_i64() == Some(me)).expect("own process listed").clone();
        assert!(p.view_action("processes", "kill", &row).unwrap_err().to_string().contains("itself"));
        assert!(p.view_action("processes", "kill", &json!({"pid": 1, "start": 0})).is_err());

        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let cpid = child.id() as i64;
        let data = p.view_data("processes").unwrap();
        let mut row =
            data["rows"].as_array().unwrap().iter().find(|r| r["pid"].as_i64() == Some(cpid)).unwrap().clone();
        let real_start = row["start"].clone();
        row["start"] = json!(1);
        assert!(p.view_action("processes", "terminate", &row).unwrap_err().to_string().contains("different process"));
        row["start"] = real_start;
        p.view_action("processes", "terminate", &row).unwrap();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn monitor_counters() {
        let c = counters();
        assert!(c.cpu_total > 0);
        let d = Monitor.view_data("monitor").unwrap();
        assert_eq!(d["series"].as_array().unwrap().len(), 8);
    }
}
