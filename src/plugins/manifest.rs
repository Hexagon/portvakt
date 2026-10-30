//! Declarative plugin manifest (`plugins/<id>.toml`).
//!
//! This file IS the plugin API. Every field is documented in docs/PLUGINS.md;
//! keep the two in sync. `Manifest::validate` is the single source of truth for
//! what a valid plugin is and is used by both the server and `portvakt plugin validate`.

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Unique id: lowercase letters, digits and dashes. Also the file name.
    pub id: String,
    /// Display name.
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Grouping in the sidebar, e.g. "Web servers", "Databases".
    #[serde(default = "default_category")]
    pub category: String,
    /// Icon name (see docs/PLUGINS.md for the list). Unknown names fall back to "app".
    #[serde(default = "default_icon")]
    pub icon: String,
    pub detect: Detect,
    pub version: Option<VersionProbe>,
    pub service: Option<Service>,
    #[serde(default)]
    pub info: Vec<InfoProbe>,
    #[serde(default)]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub files: Vec<FileSpec>,
    #[serde(default)]
    pub logs: Vec<LogSpec>,
    #[serde(default)]
    pub views: Vec<View>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Detected if at least one of these rules matches.
    #[serde(default)]
    pub any: Vec<DetectRule>,
    /// ...and all of these match (optional extra requirements).
    #[serde(default)]
    pub all: Vec<DetectRule>,
}

/// Exactly one of the fields must be set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectRule {
    /// Executable name looked up in the safe PATH, or an absolute path.
    pub binary: Option<String>,
    /// Absolute path to a file or directory (glob allowed).
    pub path: Option<String>,
    /// systemd unit file exists, e.g. "nginx.service".
    pub systemd_unit: Option<String>,
    /// A running process with this exact name (/proc/<pid>/comm).
    pub process: Option<String>,
    /// Something listens on this TCP port.
    pub port: Option<u16>,
    /// Run a command; matches if exit code is 0 and (if given) `regex` matches stdout+stderr.
    pub command: Option<Vec<String>>,
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionProbe {
    pub command: Vec<String>,
    /// First capture group is the version. Applied to stdout followed by stderr.
    pub regex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// systemd unit, e.g. "nginx.service".
    pub systemd: String,
    /// Which lifecycle actions to expose. Allowed: start, stop, restart, reload, enable, disable.
    #[serde(default = "default_service_actions")]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoProbe {
    pub label: String,
    pub command: Vec<String>,
    /// Optional; first capture group (or whole match) is shown. Otherwise trimmed output.
    pub regex: Option<String>,
    #[serde(default)]
    pub privileged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// Unique within the plugin: lowercase letters, digits, dashes.
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    /// argv. Never passed through a shell. `{param}` placeholders are substituted
    /// with validated parameter values.
    pub command: Vec<String>,
    #[serde(default)]
    pub params: Vec<Param>,
    /// Needs root. Uses `sudo -n` when `security.use_sudo` is on.
    #[serde(default)]
    pub privileged: bool,
    /// Ask the user to confirm before running.
    #[serde(default)]
    pub confirm: bool,
    /// Seconds. Max 600.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    /// Placeholder name: lowercase letters, digits, underscore.
    pub name: String,
    pub label: String,
    /// Regex the WHOLE value must match (implicitly anchored).
    pub pattern: String,
    #[serde(default)]
    pub default: Option<String>,
    /// Values starting with '-' are rejected unless this is true (prevents option injection).
    #[serde(default)]
    pub allow_dash: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    /// Absolute path; glob patterns (`*`, `?`, `[..]`) allowed.
    pub path: String,
    /// Syntax hint for the editor (e.g. "nginx", "ini", "yaml", "json", "shell").
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub readonly: bool,
    /// Run after writing; on non-zero exit the previous content is restored.
    /// `{file}` is replaced with the path that was written.
    #[serde(default)]
    pub validate: Option<Vec<String>>,
    #[serde(default)]
    pub validate_privileged: bool,
    /// Action id (or service action like "reload") to run after a successful save.
    #[serde(default)]
    pub after_save: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSpec {
    pub label: String,
    /// Log file path (glob allowed). Mutually exclusive with `journal`.
    pub path: Option<String>,
    /// systemd unit whose journal to show.
    pub journal: Option<String>,
}

/// A custom view rendered by the UI from data (plugins never ship code to the browser).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    /// Unique within the plugin.
    pub id: String,
    pub label: String,
    /// "table", "metrics" or "terminal". Only native plugins can provide metrics/terminal.
    #[serde(rename = "type")]
    pub kind: ViewKind,
    /// Where it opens: "editor" (a tab) or "panel" (bottom panel).
    #[serde(default)]
    pub location: ViewLocation,
    /// Auto-refresh interval in seconds; 0 = manual.
    #[serde(default)]
    pub refresh: u64,
    /// Show a shortcut for this view in the activity bar (left edge).
    #[serde(default)]
    pub activity: bool,
    /// Declarative table data source. Omit only in native plugins (Rust provides the data).
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub privileged: bool,
    /// How to parse `command` output: "json" (array of objects), "json-lines" (one object
    /// per line) or "columns" (whitespace separated, keys from `columns`, last column takes the rest).
    #[serde(default)]
    pub format: Option<TableFormat>,
    /// Header lines to skip for format = "columns".
    #[serde(default)]
    pub skip_lines: usize,
    /// Field that uniquely identifies a row (used by row actions).
    pub key: Option<String>,
    #[serde(default)]
    pub columns: Vec<Column>,
    #[serde(default)]
    pub row_actions: Vec<RowAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViewKind {
    Table,
    Metrics,
    Terminal,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViewLocation {
    #[default]
    Editor,
    Panel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TableFormat {
    Json,
    JsonLines,
    Columns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Column {
    pub key: String,
    pub label: String,
    /// Display hint: "text" (default), "number", "bytes", "percent", "status".
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowAction {
    /// Id of an action in this plugin (declarative) or a native row action.
    pub action: String,
    /// Maps action param name → row field name.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
    /// Label override (defaults to the action's label).
    pub label: Option<String>,
    #[serde(default)]
    pub danger: bool,
}

fn default_category() -> String {
    "Other".into()
}
fn default_icon() -> String {
    "app".into()
}
fn default_timeout() -> u64 {
    30
}
fn default_service_actions() -> Vec<String> {
    ["start", "stop", "restart"].map(String::from).to_vec()
}

pub const SERVICE_ACTIONS: &[&str] = &["start", "stop", "restart", "reload", "enable", "disable"];
pub const MAX_TIMEOUT: u64 = 600;

fn id_re() -> Regex {
    Regex::new(r"^[a-z0-9][a-z0-9-]{0,62}$").unwrap()
}
fn unit_re() -> Regex {
    Regex::new(r"^[A-Za-z0-9@._\-]+\.(service|socket|timer|target)$").unwrap()
}
fn placeholder_re() -> Regex {
    Regex::new(r"\{([a-z_][a-z0-9_]*)\}").unwrap()
}

/// Placeholders used in an argv.
pub fn placeholders(argv: &[String]) -> Vec<String> {
    let re = placeholder_re();
    argv.iter()
        .flat_map(|a| re.captures_iter(a).map(|c| c[1].to_string()).collect::<Vec<_>>())
        .collect()
}

/// Compile a param pattern so it must match the whole value.
pub fn anchored(pattern: &str) -> Result<Regex> {
    Regex::new(&format!("^(?:{pattern})$")).with_context(|| format!("invalid pattern {pattern:?}"))
}

fn check_argv(what: &str, argv: &[String], allowed: &HashSet<String>) -> Result<()> {
    let Some(first) = argv.first() else { bail!("{what}: command is empty") };
    if first.is_empty() || (first.contains('/') && !first.starts_with('/')) {
        bail!("{what}: command[0] must be a bare program name or an absolute path, got {first:?}");
    }
    if first.contains('{') {
        bail!("{what}: the program itself cannot be a placeholder");
    }
    for p in placeholders(argv) {
        if !allowed.contains(&p) {
            bail!("{what}: placeholder {{{p}}} is not a declared param");
        }
    }
    if argv.iter().any(|a| a.contains('\0')) {
        bail!("{what}: NUL byte in argument");
    }
    Ok(())
}

fn check_path(what: &str, p: &str) -> Result<()> {
    if !p.starts_with('/') {
        bail!("{what}: path must be absolute: {p:?}");
    }
    if p.split('/').any(|c| c == "..") {
        bail!("{what}: '..' is not allowed in paths: {p:?}");
    }
    glob::Pattern::new(p).with_context(|| format!("{what}: bad glob {p:?}"))?;
    Ok(())
}

impl DetectRule {
    fn set_count(&self) -> usize {
        [
            self.binary.is_some(),
            self.path.is_some(),
            self.systemd_unit.is_some(),
            self.process.is_some(),
            self.port.is_some(),
            self.command.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count()
    }

    fn validate(&self) -> Result<()> {
        if self.set_count() != 1 {
            bail!("detect rule must set exactly one of binary/path/systemd_unit/process/port/command: {self:?}");
        }
        if self.regex.is_some() && self.command.is_none() {
            bail!("detect rule: `regex` only applies to `command`");
        }
        if let Some(b) = &self.binary
            && (b.is_empty() || (b.contains('/') && !b.starts_with('/'))) {
                bail!("detect binary must be a bare name or absolute path: {b:?}");
            }
        if let Some(p) = &self.path {
            check_path("detect path", p)?;
        }
        if let Some(u) = &self.systemd_unit
            && !unit_re().is_match(u) {
                bail!("detect systemd_unit looks invalid: {u:?}");
            }
        if let Some(p) = &self.process
            && (p.is_empty() || p.len() > 15 || p.contains('/')) {
                bail!("detect process must be a comm name (max 15 chars): {p:?}");
            }
        if let Some(c) = &self.command {
            check_argv("detect command", c, &HashSet::new())?;
        }
        if let Some(r) = &self.regex {
            Regex::new(r).context("detect regex")?;
        }
        Ok(())
    }
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self> {
        let m: Manifest = toml::from_str(text)?;
        m.validate()?;
        Ok(m)
    }

    /// All action ids this plugin exposes, including service lifecycle actions.
    pub fn action_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.actions.iter().map(|a| a.id.clone()).collect();
        if let Some(s) = &self.service {
            ids.extend(s.actions.iter().cloned());
        }
        ids
    }

    pub fn validate(&self) -> Result<()> {
        if !id_re().is_match(&self.id) {
            bail!("id {:?} must match [a-z0-9][a-z0-9-]*", self.id);
        }
        if self.name.trim().is_empty() {
            bail!("name is empty");
        }
        if self.detect.any.is_empty() && self.detect.all.is_empty() {
            bail!("detect needs at least one rule in `any` or `all`");
        }
        for r in self.detect.any.iter().chain(&self.detect.all) {
            r.validate()?;
        }
        if let Some(v) = &self.version {
            check_argv("version", &v.command, &HashSet::new())?;
            let re = Regex::new(&v.regex).context("version regex")?;
            if re.captures_len() < 2 {
                bail!("version regex needs a capture group");
            }
        }
        let mut ids = HashSet::new();
        if let Some(s) = &self.service {
            if !unit_re().is_match(&s.systemd) {
                bail!("service.systemd looks invalid: {:?}", s.systemd);
            }
            for a in &s.actions {
                if !SERVICE_ACTIONS.contains(&a.as_str()) {
                    bail!("service action {a:?} not one of {SERVICE_ACTIONS:?}");
                }
                if !ids.insert(a.clone()) {
                    bail!("duplicate action id {a:?}");
                }
            }
        }
        for i in &self.info {
            check_argv(&format!("info {:?}", i.label), &i.command, &HashSet::new())?;
            if let Some(r) = &i.regex {
                Regex::new(r).context("info regex")?;
            }
        }
        let param_re = Regex::new(r"^[a-z_][a-z0-9_]*$").unwrap();
        for a in &self.actions {
            if !id_re().is_match(&a.id) {
                bail!("action id {:?} must match [a-z0-9][a-z0-9-]*", a.id);
            }
            if !ids.insert(a.id.clone()) {
                bail!("duplicate action id {:?} (service actions count too)", a.id);
            }
            if a.timeout == 0 || a.timeout > MAX_TIMEOUT {
                bail!("action {:?}: timeout must be 1..={MAX_TIMEOUT}", a.id);
            }
            let mut names = HashSet::new();
            for p in &a.params {
                if !param_re.is_match(&p.name) {
                    bail!("action {:?}: bad param name {:?}", a.id, p.name);
                }
                if p.name == "file" {
                    bail!("action {:?}: param name 'file' is reserved", a.id);
                }
                if !names.insert(p.name.clone()) {
                    bail!("action {:?}: duplicate param {:?}", a.id, p.name);
                }
                let re = anchored(&p.pattern)?;
                if let Some(d) = &p.default
                    && !re.is_match(d) {
                        bail!("action {:?}: default for {:?} does not match its pattern", a.id, p.name);
                    }
            }
            check_argv(&format!("action {:?}", a.id), &a.command, &names)?;
        }
        let file_ph: HashSet<String> = ["file".to_string()].into();
        for f in &self.files {
            check_path("file", &f.path)?;
            if let Some(v) = &f.validate {
                check_argv("file validate", v, &file_ph)?;
            }
            if let Some(a) = &f.after_save {
                if !ids.contains(a) {
                    bail!("file {:?}: after_save refers to unknown action {a:?}", f.path);
                }
                if self.actions.iter().any(|x| &x.id == a && !x.params.is_empty()) {
                    bail!("file {:?}: after_save action {a:?} must not take params", f.path);
                }
            }
            if f.readonly && (f.validate.is_some() || f.after_save.is_some()) {
                bail!("file {:?}: readonly files cannot have validate/after_save", f.path);
            }
        }
        let mut view_ids = HashSet::new();
        for v in &self.views {
            if !id_re().is_match(&v.id) || !view_ids.insert(v.id.clone()) {
                bail!("view id {:?} invalid or duplicate", v.id);
            }
            if v.kind != ViewKind::Table && v.command.is_some() {
                bail!("view {:?}: only table views can have a command", v.id);
            }
            if let Some(c) = &v.command {
                check_argv(&format!("view {:?}", v.id), c, &HashSet::new())?;
                let Some(fmt) = v.format else { bail!("view {:?}: `format` is required with `command`", v.id) };
                if fmt == TableFormat::Columns && v.columns.is_empty() {
                    bail!("view {:?}: format \"columns\" needs `columns`", v.id);
                }
            }
            if v.refresh > 0 && v.refresh < 2 {
                bail!("view {:?}: refresh must be 0 or >= 2 seconds", v.id);
            }
            for ra in &v.row_actions {
                if v.key.is_none() {
                    bail!("view {:?}: row_actions need `key`", v.id);
                }
                // Declarative views must reference a real action and supply every param.
                if v.command.is_some() {
                    let Some(a) = self.actions.iter().find(|a| a.id == ra.action) else {
                        bail!("view {:?}: row action {:?} is not an action of this plugin", v.id, ra.action);
                    };
                    for p in &a.params {
                        if !ra.params.contains_key(&p.name) && p.default.is_none() {
                            bail!("view {:?}: row action {:?} does not map param {:?}", v.id, ra.action, p.name);
                        }
                    }
                    for k in ra.params.keys() {
                        if !a.params.iter().any(|p| &p.name == k) {
                            bail!("view {:?}: row action {:?} maps unknown param {k:?}", v.id, ra.action);
                        }
                    }
                }
            }
        }
        for l in &self.logs {
            match (&l.path, &l.journal) {
                (Some(p), None) => check_path("log", p)?,
                (None, Some(u)) => {
                    if !unit_re().is_match(u) {
                        bail!("log journal unit looks invalid: {u:?}");
                    }
                }
                _ => bail!("log {:?}: set exactly one of path/journal", l.label),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
        id = "demo"
        name = "Demo"
        [detect]
        any = [{ binary = "demo" }, { path = "/etc/demo/*.conf" }]
        [version]
        command = ["demo", "--version"]
        regex = 'demo (\S+)'
        [service]
        systemd = "demo.service"
        actions = ["start", "stop", "reload"]
        [[actions]]
        id = "logs"
        label = "Logs"
        command = ["journalctl", "-u", "demo", "-n", "{lines}"]
        [[actions.params]]
        name = "lines"
        label = "Lines"
        pattern = "[0-9]{1,4}"
        default = "100"
        [[files]]
        path = "/etc/demo/demo.conf"
        validate = ["demo", "-t", "-c", "{file}"]
        after_save = "reload"
    "#;

    #[test]
    fn valid_manifest() {
        let m = Manifest::parse(OK).unwrap();
        assert_eq!(m.action_ids(), vec!["logs", "start", "stop", "reload"]);
    }

    fn bad(replace: &str, with: &str) -> String {
        let s = OK.replacen(replace, with, 1);
        assert_ne!(s, OK, "replacement {replace:?} did not apply");
        Manifest::parse(&s).unwrap_err().to_string()
    }

    #[test]
    fn rejects_bad_manifests() {
        assert!(bad(r#"id = "demo""#, r#"id = "Demo!""#).contains("id"));
        assert!(bad("{lines}", "{nope}").contains("not a declared param"));
        assert!(bad(r#"["demo", "--version"]"#, r#"["./demo"]"#).contains("bare program"));
        assert!(bad(r#"after_save = "reload""#, r#"after_save = "nuke""#).contains("unknown action"));
        assert!(bad(r#"path = "/etc/demo/demo.conf""#, r#"path = "/etc/../shadow""#).contains(".."));
        assert!(bad(r#"default = "100""#, r#"default = "abc""#).contains("default"));
        assert!(bad(r#""stop", "reload""#, r#""stop", "explode""#).contains("service action"));
        assert!(bad(r#"{ binary = "demo" }"#, r#"{ binary = "demo", port = 1 }"#).contains("exactly one"));
        assert!(bad("id = \"demo\"\n", "id = \"demo\"\nbogus = 1\n").contains("unknown field"));
    }

    #[test]
    fn anchoring() {
        let re = anchored("[0-9]+").unwrap();
        assert!(re.is_match("123"));
        assert!(!re.is_match("123; rm -rf /"));
        assert!(!re.is_match("1\n2"));
        let alt = anchored("a|b").unwrap();
        assert!(!alt.is_match("ax"), "alternation must stay inside the anchors");
    }
}
