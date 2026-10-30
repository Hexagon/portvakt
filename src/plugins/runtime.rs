//! Executing plugin capabilities: actions, service control, info probes,
//! file read/write (with backup, validation and rollback) and logs.

use super::manifest::{Action, Column, FileSpec, Manifest, TableFormat, View, ViewKind, ViewLocation};
use super::Plugin;
use crate::exec::{self, Output};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_FILE: u64 = 2 * 1024 * 1024;
const LOG_TAIL: u64 = 256 * 1024;

#[derive(Clone, Copy)]
pub struct ExecPolicy {
    pub use_sudo: bool,
}

#[derive(Serialize)]
pub struct ActionView {
    pub id: String,
    pub label: String,
    pub description: String,
    pub confirm: bool,
    pub privileged: bool,
    pub params: Vec<ParamView>,
    pub available: bool,
}

#[derive(Serialize)]
pub struct ParamView {
    pub name: String,
    pub label: String,
    pub default: Option<String>,
    pub pattern: String,
}

#[derive(Serialize)]
pub struct FileView {
    pub path: String,
    pub language: Option<String>,
    pub readonly: bool,
    pub validated: bool,
}

/// A resolved action: built-in service verb or manifest action.
fn service_action(m: &Manifest, id: &str) -> Option<Action> {
    let s = m.service.as_ref()?;
    if !s.actions.iter().any(|a| a == id) {
        return None;
    }
    Some(Action {
        id: id.into(),
        label: format!("{}{}", id[..1].to_uppercase(), &id[1..]),
        description: format!("systemctl {id} {}", s.systemd),
        command: vec!["systemctl".into(), id.into(), s.systemd.clone()],
        params: vec![],
        privileged: true,
        confirm: matches!(id, "stop" | "disable" | "restart"),
        timeout: 90,
    })
}

pub fn find_action(m: &Manifest, id: &str) -> Option<Action> {
    m.actions.iter().find(|a| a.id == id).cloned().or_else(|| service_action(m, id))
}

pub fn actions(m: &Manifest) -> Vec<ActionView> {
    let mut list: Vec<Action> = Vec::new();
    if let Some(s) = &m.service {
        list.extend(s.actions.iter().filter_map(|a| service_action(m, a)));
    }
    list.extend(m.actions.iter().cloned());
    list.into_iter()
        .map(|a| ActionView {
            available: exec::resolve(&a.command[0]).is_some(),
            id: a.id,
            label: a.label,
            description: a.description,
            confirm: a.confirm,
            privileged: a.privileged,
            params: a
                .params
                .into_iter()
                .map(|p| ParamView { name: p.name, label: p.label, default: p.default, pattern: p.pattern })
                .collect(),
        })
        .collect()
}

/// Substitute validated params into the argv. Every value must fully match its
/// pattern, and may not start with '-' unless allowed.
pub fn render_argv(action: &Action, values: &HashMap<String, String>) -> Result<Vec<String>> {
    let mut resolved = HashMap::new();
    for p in &action.params {
        let v = values.get(&p.name).cloned().or_else(|| p.default.clone()).ok_or_else(|| anyhow!("missing parameter {:?}", p.label))?;
        if !super::manifest::anchored(&p.pattern)?.is_match(&v) {
            bail!("parameter {:?} does not match the allowed pattern {}", p.label, p.pattern);
        }
        if v.starts_with('-') && !p.allow_dash {
            bail!("parameter {:?} may not start with '-'", p.label);
        }
        resolved.insert(p.name.clone(), v);
    }
    for k in values.keys() {
        if !resolved.contains_key(k) {
            bail!("unknown parameter {k:?}");
        }
    }
    Ok(substitute(&action.command, &resolved))
}

fn substitute(argv: &[String], vals: &HashMap<String, String>) -> Vec<String> {
    let re = regex::Regex::new(r"\{([a-z_][a-z0-9_]*)\}").unwrap();
    argv.iter()
        .map(|a| re.replace_all(a, |c: &regex::Captures| vals.get(&c[1]).cloned().unwrap_or_default()).into_owned())
        .collect()
}

pub async fn run_action(m: &Manifest, id: &str, values: &HashMap<String, String>, pol: ExecPolicy) -> Result<Output> {
    let action = find_action(m, id).ok_or_else(|| anyhow!("unknown action {id:?}"))?;
    let argv = render_argv(&action, values)?;
    let argv = exec::prepare(&argv, action.privileged, pol.use_sudo).map_err(|e| anyhow!(e))?;
    Ok(exec::run(argv, Duration::from_secs(action.timeout)).await)
}

#[derive(Serialize, Default)]
pub struct ServiceStatus {
    pub unit: String,
    pub active: String,
    pub sub: String,
    pub enabled: String,
    pub pid: String,
    pub description: String,
}

pub async fn service_status(m: &Manifest) -> Option<ServiceStatus> {
    let unit = m.service.as_ref()?.systemd.clone();
    let argv = exec::prepare(
        &["systemctl", "show", &unit, "--no-pager", "--property=ActiveState,SubState,UnitFileState,MainPID,Description"]
            .map(String::from),
        false,
        false,
    )
    .ok()?;
    let out = exec::run(argv, Duration::from_secs(5)).await;
    let kv: HashMap<&str, &str> = out.stdout.lines().filter_map(|l| l.split_once('=')).collect();
    let g = |k: &str| kv.get(k).copied().unwrap_or("").to_string();
    Some(ServiceStatus {
        unit,
        active: g("ActiveState"),
        sub: g("SubState"),
        enabled: g("UnitFileState"),
        pid: g("MainPID"),
        description: g("Description"),
    })
}

pub async fn info(p: &Plugin, pol: ExecPolicy) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if let Some(n) = &p.native {
        let n = n.clone();
        rows.extend(tokio::task::spawn_blocking(move || n.info()).await.unwrap_or_default());
    }
    let futs = p.manifest.info.iter().map(|probe| async move {
        let value = match exec::prepare(&probe.command, probe.privileged, pol.use_sudo) {
            Err(e) => e,
            Ok(argv) => {
                let out = exec::run(argv, Duration::from_secs(10)).await;
                let text = if out.stdout.trim().is_empty() { out.stderr.clone() } else { out.stdout.clone() };
                match &probe.regex {
                    Some(r) => regex::Regex::new(r)
                        .ok()
                        .and_then(|re| re.captures(&text).map(|c| c.get(1).unwrap_or(c.get(0).unwrap()).as_str().to_string()))
                        .unwrap_or_else(|| "—".into()),
                    None => {
                        let t: String = text.trim().lines().take(20).collect::<Vec<_>>().join("\n");
                        if t.is_empty() { "—".into() } else { t }
                    }
                }
            }
        };
        (probe.label.clone(), value)
    });
    rows.extend(futures_util::future::join_all(futs).await);
    rows
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Concrete files declared by the plugin (globs expanded). Only these may be opened.
pub fn files(m: &Manifest) -> Vec<FileView> {
    let mut out = Vec::new();
    for spec in &m.files {
        for path in expand(&spec.path) {
            if out.iter().any(|f: &FileView| f.path == path) {
                continue;
            }
            out.push(FileView {
                path,
                language: spec.language.clone(),
                readonly: spec.readonly,
                validated: spec.validate.is_some(),
            });
        }
    }
    out
}

fn expand(pattern: &str) -> Vec<String> {
    let mut v: Vec<String> = glob::glob(pattern)
        .map(|g| g.flatten().filter(|p| p.is_file()).map(|p| p.display().to_string()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn spec_for<'a>(m: &'a Manifest, path: &str) -> Result<&'a FileSpec> {
    m.files
        .iter()
        .find(|s| expand(&s.path).iter().any(|p| p == path))
        .ok_or_else(|| anyhow!("file is not managed by this plugin"))
}

/// Resolve symlinks, refusing links planted by unprivileged users.
fn real_path(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    let lmeta = std::fs::symlink_metadata(p)?;
    if lmeta.file_type().is_symlink() {
        let me = unsafe { libc::geteuid() };
        if lmeta.uid() != 0 && lmeta.uid() != me {
            bail!("refusing to follow symlink owned by uid {}", lmeta.uid());
        }
    }
    let real = std::fs::canonicalize(p)?;
    if !real.is_file() {
        bail!("not a regular file");
    }
    Ok(real)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Serialize)]
pub struct FileContent {
    pub path: String,
    pub content: String,
    pub sha256: String,
    pub readonly: bool,
    pub language: Option<String>,
}

pub fn read_file(m: &Manifest, path: &str) -> Result<FileContent> {
    let spec = spec_for(m, path)?;
    let real = real_path(path)?;
    let meta = std::fs::metadata(&real)?;
    if meta.len() > MAX_FILE {
        bail!("file is larger than {} MiB", MAX_FILE / 1024 / 1024);
    }
    let data = std::fs::read(&real)?;
    let content = String::from_utf8(data).map_err(|_| anyhow!("file is not UTF-8 text"))?;
    Ok(FileContent {
        path: path.to_string(),
        sha256: sha256_hex(content.as_bytes()),
        content,
        readonly: spec.readonly,
        language: spec.language.clone(),
    })
}

#[derive(Serialize)]
pub struct SaveResult {
    pub sha256: String,
    pub backup: String,
    pub validation: Option<Output>,
    pub after_save: Option<Output>,
}

pub enum SaveError {
    /// File changed on disk since it was opened.
    Conflict,
    /// Validation failed; original content was restored.
    Invalid(Output),
    Other(anyhow::Error),
}

impl From<anyhow::Error> for SaveError {
    fn from(e: anyhow::Error) -> Self {
        SaveError::Other(e)
    }
}
impl From<std::io::Error> for SaveError {
    fn from(e: std::io::Error) -> Self {
        SaveError::Other(e.into())
    }
}

pub async fn write_file(
    m: &Manifest,
    path: &str,
    content: &str,
    base_sha256: &str,
    backup_dir: &Path,
    pol: ExecPolicy,
) -> std::result::Result<SaveResult, SaveError> {
    let spec = spec_for(m, path)?.clone();
    if spec.readonly {
        return Err(anyhow!("file is read-only").into());
    }
    if content.len() as u64 > MAX_FILE {
        return Err(anyhow!("content too large").into());
    }
    let real = real_path(path)?;
    let old = std::fs::read(&real)?;
    if sha256_hex(&old) != base_sha256 {
        return Err(SaveError::Conflict);
    }
    let backup = backup(backup_dir, &m.id, &real, &old)?;
    atomic_replace(&real, content.as_bytes())?;

    let mut validation = None;
    if let Some(v) = &spec.validate {
        let mut vals = HashMap::new();
        vals.insert("file".to_string(), real.display().to_string());
        let argv = exec::prepare(&substitute(v, &vals), spec.validate_privileged, pol.use_sudo).map_err(|e| anyhow!(e))?;
        let out = exec::run(argv, Duration::from_secs(60)).await;
        if !out.success() {
            atomic_replace(&real, &old).context("RESTORE FAILED after validation error")?;
            return Err(SaveError::Invalid(out));
        }
        validation = Some(out);
    }
    let after_save = match &spec.after_save {
        Some(id) => Some(run_action(m, id, &HashMap::new(), pol).await?),
        None => None,
    };
    Ok(SaveResult { sha256: sha256_hex(content.as_bytes()), backup: backup.display().to_string(), validation, after_save })
}

fn backup(dir: &Path, plugin: &str, real: &Path, data: &[u8]) -> Result<PathBuf> {
    let d = dir.join(plugin);
    std::fs::create_dir_all(&d)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
    let name = real.display().to_string().trim_start_matches('/').replace('/', "__");
    let file = d.join(format!("{name}.{}", crate::auth::unix_now()));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file)
        .or_else(|_| {
            // Same-second save: add a random suffix.
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(file.with_extension(crate::auth::random_token(4)))
        })?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(file)
}

/// Write via temp file + rename in the same directory, keeping mode and ownership.
fn atomic_replace(real: &Path, data: &[u8]) -> Result<()> {
    let meta = std::fs::metadata(real)?;
    let dir = real.parent().ok_or_else(|| anyhow!("no parent dir"))?;
    let tmp = dir.join(format!(".portvakt-{}", crate::auth::random_token(8)));
    let res = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        if exec::is_root() {
            std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid()))?;
        }
        f.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o7777))?;
        f.sync_all()?;
        std::fs::rename(&tmp, real)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ViewView {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: ViewKind,
    pub location: ViewLocation,
    pub refresh: u64,
    pub activity: bool,
    pub key: Option<String>,
    pub columns: Vec<Column>,
    pub row_actions: Vec<RowActionView>,
}

#[derive(Serialize)]
pub struct RowActionView {
    pub action: String,
    pub label: String,
    pub danger: bool,
    pub confirm: bool,
}

pub fn views(m: &Manifest) -> Vec<ViewView> {
    m.views
        .iter()
        .map(|v| ViewView {
            id: v.id.clone(),
            label: v.label.clone(),
            kind: v.kind,
            location: v.location,
            refresh: v.refresh,
            activity: v.activity,
            key: v.key.clone(),
            columns: v.columns.clone(),
            row_actions: v
                .row_actions
                .iter()
                .map(|ra| {
                    let a = m.actions.iter().find(|a| a.id == ra.action);
                    RowActionView {
                        action: ra.action.clone(),
                        label: ra.label.clone().or_else(|| a.map(|a| a.label.clone())).unwrap_or_else(|| ra.action.clone()),
                        danger: ra.danger,
                        // Native row actions always confirm; declarative follow the action.
                        confirm: a.map(|a| a.confirm).unwrap_or(true) || ra.danger,
                    }
                })
                .collect(),
        })
        .collect()
}

fn view<'a>(m: &'a Manifest, id: &str) -> Result<&'a View> {
    m.views.iter().find(|v| v.id == id).ok_or_else(|| anyhow!("unknown view {id:?}"))
}

pub async fn view_data(p: &Plugin, id: &str, pol: ExecPolicy) -> Result<serde_json::Value> {
    let v = view(&p.manifest, id)?.clone();
    let Some(cmd) = &v.command else {
        let n = p.native.clone().ok_or_else(|| anyhow!("view has no data source"))?;
        let id = id.to_string();
        return tokio::task::spawn_blocking(move || n.view_data(&id)).await?;
    };
    let argv = exec::prepare(cmd, v.privileged, pol.use_sudo).map_err(|e| anyhow!(e))?;
    let out = exec::run(argv, Duration::from_secs(30)).await;
    if !out.success() {
        bail!("command failed: {}", out.combined().trim());
    }
    let rows = parse_table(&v, &out.stdout)?;
    Ok(serde_json::json!({ "rows": rows }))
}

pub fn parse_table(v: &View, text: &str) -> Result<Vec<serde_json::Value>> {
    use serde_json::Value;
    let rows: Vec<Value> = match v.format.unwrap_or(TableFormat::Json) {
        TableFormat::Json => match serde_json::from_str::<Value>(text)? {
            Value::Array(a) => a,
            _ => bail!("expected a JSON array"),
        },
        TableFormat::JsonLines => text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?,
        TableFormat::Columns => text
            .lines()
            .skip(v.skip_lines)
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let n = v.columns.len();
                let parts: Vec<&str> = l.split_whitespace().collect();
                let mut obj = serde_json::Map::new();
                for (i, c) in v.columns.iter().enumerate() {
                    let val = if i + 1 == n { parts.get(i..).map(|r| r.join(" ")).unwrap_or_default() } else { parts.get(i).unwrap_or(&"").to_string() };
                    obj.insert(c.key.clone(), Value::String(val));
                }
                Value::Object(obj)
            })
            .collect(),
    };
    Ok(rows.into_iter().filter(|r| r.is_object()).take(5000).collect())
}

/// Run a row action. For declarative views the row's fields are mapped to the action's
/// params and go through the normal param validation.
pub async fn view_action(p: &Plugin, view_id: &str, action: &str, row: &serde_json::Value, pol: ExecPolicy) -> Result<String> {
    let v = view(&p.manifest, view_id)?.clone();
    let ra = v.row_actions.iter().find(|r| r.action == action).ok_or_else(|| anyhow!("unknown row action"))?;
    if v.command.is_none() {
        let n = p.native.clone().ok_or_else(|| anyhow!("no handler"))?;
        let (vid, a, r) = (view_id.to_string(), action.to_string(), row.clone());
        return tokio::task::spawn_blocking(move || n.view_action(&vid, &a, &r)).await?;
    }
    let mut params = HashMap::new();
    for (param, field) in &ra.params {
        let val = match &row[field] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => bail!("row field {field:?} missing"),
        };
        params.insert(param.clone(), val);
    }
    let out = run_action(&p.manifest, action, &params, pol).await?;
    if !out.success() {
        bail!("{}", out.combined().trim());
    }
    Ok(out.combined())
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LogView {
    pub index: usize,
    pub label: String,
    pub source: String,
}

pub fn logs(m: &Manifest) -> Vec<LogView> {
    m.logs
        .iter()
        .enumerate()
        .map(|(i, l)| LogView {
            index: i,
            label: l.label.clone(),
            source: l.path.clone().unwrap_or_else(|| format!("journal: {}", l.journal.clone().unwrap_or_default())),
        })
        .collect()
}

pub async fn read_log(m: &Manifest, index: usize, pol: ExecPolicy) -> Result<String> {
    let spec = m.logs.get(index).ok_or_else(|| anyhow!("no such log"))?;
    if let Some(unit) = &spec.journal {
        let argv = ["journalctl", "-u", unit, "-n", "500", "--no-pager", "-o", "short-iso"].map(String::from);
        let argv = exec::prepare(&argv, true, pol.use_sudo).map_err(|e| anyhow!(e))?;
        let out = exec::run(argv, Duration::from_secs(15)).await;
        return Ok(out.combined());
    }
    let pattern = spec.path.as_deref().unwrap_or_default();
    let mut paths = expand(pattern);
    // Newest file of a glob first.
    paths.sort_by_key(|p| std::cmp::Reverse(std::fs::metadata(p).and_then(|m| m.modified()).ok()));
    let path = paths.first().ok_or_else(|| anyhow!("log file not found: {pattern}"))?;
    let real = real_path(path)?;
    let mut f = std::fs::File::open(&real)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(LOG_TAIL);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 {
        if let Some(i) = text.find('\n') {
            text = text[i + 1..].to_string();
        }
        text = format!("… showing last {} KiB of {}\n{text}", LOG_TAIL / 1024, real.display());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(dir: &Path) -> Manifest {
        let text = format!(
            r#"
            id = "t"
            name = "T"
            [detect]
            any = [{{ binary = "sh" }}]
            [[actions]]
            id = "echo"
            label = "Echo"
            command = ["echo", "hello {{who}}"]
            [[actions.params]]
            name = "who"
            label = "Who"
            pattern = "[a-z]+"
            [[files]]
            path = "{d}/*.conf"
            validate = ["grep", "-q", "ok", "{{file}}"]
            [[files]]
            path = "{d}/ro.txt"
            readonly = true
            "#,
            d = dir.display()
        );
        Manifest::parse(&text).unwrap()
    }

    #[test]
    fn table_formats() {
        let mut v: View = toml::from_str(
            "id='t'\nlabel='T'\ntype='table'\ncommand=['x']\nformat='columns'\nskip_lines=1\ncolumns=[{key='a',label='A'},{key='rest',label='R'}]",
        )
        .unwrap();
        let rows = parse_table(&v, "HEAD ER\n1 hello world\n\n2 x\n").unwrap();
        assert_eq!(rows[0]["rest"], "hello world");
        assert_eq!(rows.len(), 2);
        v.format = Some(TableFormat::JsonLines);
        assert_eq!(parse_table(&v, "{\"a\":1}\n{\"a\":2}\n").unwrap().len(), 2);
        v.format = Some(TableFormat::Json);
        assert!(parse_table(&v, "{}").is_err());
    }

    #[tokio::test]
    async fn params_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let m = manifest(dir.path());
        let pol = ExecPolicy { use_sudo: false };
        let mut v = HashMap::new();
        v.insert("who".to_string(), "world".to_string());
        assert_eq!(run_action(&m, "echo", &v, pol).await.unwrap().stdout, "hello world\n");
        v.insert("who".to_string(), "x; id".to_string());
        assert!(run_action(&m, "echo", &v, pol).await.is_err());
        v.insert("who".to_string(), "world".to_string());
        v.insert("extra".to_string(), "1".to_string());
        assert!(run_action(&m, "echo", &v, pol).await.is_err());
    }

    #[tokio::test]
    async fn file_write_validate_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let backups = tempfile::tempdir().unwrap();
        let conf = dir.path().join("a.conf");
        std::fs::write(&conf, "ok v1\n").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::write(dir.path().join("ro.txt"), "x").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "x").unwrap();
        let m = manifest(dir.path());
        let pol = ExecPolicy { use_sudo: false };
        let path = conf.display().to_string();

        let f = read_file(&m, &path).unwrap();
        assert_eq!(f.content, "ok v1\n");
        // Not declared → refused.
        assert!(read_file(&m, &dir.path().join("secret.txt").display().to_string()).is_err());
        assert!(read_file(&m, "/etc/shadow").is_err());

        // Stale hash → conflict.
        assert!(matches!(write_file(&m, &path, "ok v2\n", "deadbeef", backups.path(), pol).await, Err(SaveError::Conflict)));
        // Valid save.
        let r = write_file(&m, &path, "ok v2\n", &f.sha256, backups.path(), pol).await.ok().unwrap();
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), "ok v2\n");
        assert_eq!(std::fs::read_to_string(&r.backup).unwrap(), "ok v1\n");
        assert_eq!(std::fs::metadata(&conf).unwrap().mode() & 0o777, 0o640);
        // Invalid content → rolled back.
        let res = write_file(&m, &path, "bad\n", &r.sha256, backups.path(), pol).await;
        assert!(matches!(res, Err(SaveError::Invalid(_))));
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), "ok v2\n");
        // Read-only.
        let ro = dir.path().join("ro.txt").display().to_string();
        let h = read_file(&m, &ro).unwrap().sha256;
        assert!(write_file(&m, &ro, "y", &h, backups.path(), pol).await.is_err());
    }
}
