//! Plugin registry and runtime.
//!
//! Plugins come from three sources, later ones overriding earlier by `id`:
//! 1. native plugins compiled in (`native.rs`),
//! 2. built-in TOML manifests embedded from `plugins/` at build time,
//! 3. TOML manifests in `plugins.dirs` (trust-checked: must not be writable by others).

pub mod detect;
pub mod manifest;
pub mod native;
pub mod runtime;

use anyhow::{Context, Result, bail};
use detect::Detection;
use manifest::Manifest;
use rust_embed::RustEmbed;
use serde::Serialize;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(RustEmbed)]
#[folder = "plugins/"]
#[include = "*.toml"]
struct BuiltinPlugins;

#[derive(Clone, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "lowercase")]
pub enum Source {
    Native,
    Builtin,
    File(PathBuf),
}

#[derive(Clone)]
pub struct Plugin {
    pub manifest: Arc<Manifest>,
    pub source: Source,
    pub native: Option<Arc<dyn native::NativePlugin>>,
}

pub struct Registry {
    pub plugins: Vec<Plugin>,
    detections: RwLock<HashMap<String, Detection>>,
}

/// Load every plugin. Invalid manifests are reported and skipped (never fatal),
/// except that an untrusted plugin directory aborts startup.
pub fn load_all(dirs: &[PathBuf], disabled: &[String]) -> Result<(Vec<Plugin>, Vec<String>)> {
    let mut map: HashMap<String, Plugin> = HashMap::new();
    let mut errors = Vec::new();
    for n in native::all() {
        match native::parse(n.as_ref()) {
            Ok(m) => {
                map.insert(
                    m.id.clone(),
                    Plugin { manifest: Arc::new(m), source: Source::Native, native: Some(Arc::from(n)) },
                );
            }
            Err(e) => errors.push(format!("native plugin: {e:#}")),
        }
    }
    for name in BuiltinPlugins::iter() {
        let file = BuiltinPlugins::get(&name).unwrap();
        let text = String::from_utf8_lossy(&file.data);
        match Manifest::parse(&text) {
            Ok(m) => {
                if format!("{}.toml", m.id) != name {
                    errors.push(format!("builtin {name}: file name must be <id>.toml"));
                    continue;
                }
                if let Err(e) = check_declarative(&m) {
                    errors.push(format!("builtin {name}: {e:#}"));
                    continue;
                }
                map.insert(m.id.clone(), Plugin { manifest: Arc::new(m), source: Source::Builtin, native: None });
            }
            Err(e) => errors.push(format!("builtin {name}: {e:#}")),
        }
    }
    for dir in dirs {
        check_trusted(dir)?;
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading plugin dir {}", dir.display()))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .collect();
        entries.sort();
        for path in entries {
            let res = check_trusted(&path)
                .and_then(|_| std::fs::read_to_string(&path).map_err(Into::into))
                .and_then(|t| Manifest::parse(&t))
                .and_then(|m| check_declarative(&m).map(|_| m));
            match res {
                Ok(m) => {
                    // An external manifest may override a builtin, but not a native plugin's hooks.
                    let native = map.get(&m.id).and_then(|p| p.native.clone());
                    if native.is_some() {
                        errors.push(format!("{}: cannot override native plugin {:?}", path.display(), m.id));
                        continue;
                    }
                    map.insert(
                        m.id.clone(),
                        Plugin { manifest: Arc::new(m), source: Source::File(path), native: None },
                    );
                }
                Err(e) => errors.push(format!("{}: {e:#}", path.display())),
            }
        }
    }
    let mut plugins: Vec<Plugin> = map.into_values().filter(|p| !disabled.contains(&p.manifest.id)).collect();
    plugins.sort_by_key(|a| a.manifest.name.to_lowercase());
    Ok((plugins, errors))
}

/// Rules that only apply to TOML-only plugins (no Rust hooks to provide view data).
fn check_declarative(m: &Manifest) -> Result<()> {
    for v in &m.views {
        if v.kind != manifest::ViewKind::Table || v.command.is_none() {
            bail!("view {:?}: declarative plugins can only have table views with a `command`", v.id);
        }
    }
    Ok(())
}

/// A plugin file can make portvakt run arbitrary commands, so it must be as
/// protected as the binary itself: owned by root or us, not group/world-writable.
pub fn check_trusted(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let me = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != me {
        bail!("{} is owned by uid {}; must be root or portvakt's user", path.display(), meta.uid());
    }
    if meta.mode() & 0o022 != 0 {
        bail!("{} is writable by group/others (mode {:o}); refusing to load", path.display(), meta.mode() & 0o777);
    }
    Ok(())
}

impl Registry {
    pub fn new(plugins: Vec<Plugin>) -> Self {
        Self { plugins, detections: RwLock::new(HashMap::new()) }
    }

    pub fn get(&self, id: &str) -> Option<&Plugin> {
        self.plugins.iter().find(|p| p.manifest.id == id)
    }

    pub async fn rescan(&self) {
        let futs = self.plugins.iter().map(|p| {
            let m = p.manifest.clone();
            async move { (m.id.clone(), detect::detect(&m).await) }
        });
        let results = futures_util::future::join_all(futs).await;
        *self.detections.write().await = results.into_iter().collect();
    }

    pub async fn detection(&self, id: &str) -> Detection {
        self.detections.read().await.get(id).cloned().unwrap_or_default()
    }

    pub async fn is_detected(&self, id: &str) -> bool {
        self.detections.read().await.get(id).is_some_and(|d| d.detected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_plugins_all_valid() {
        let (plugins, errors) = load_all(&[], &[]).unwrap();
        assert!(errors.is_empty(), "plugin errors: {errors:#?}");
        assert!(plugins.len() >= 2);
    }

    #[test]
    fn untrusted_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load_all(&[dir.path().to_path_buf()], &[]).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = dir.path().join("x.toml");
        std::fs::write(&f, "id = \"x\"\nname = \"X\"\n[detect]\nany = [{ binary = \"sh\" }]\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let (_, errors) = load_all(&[dir.path().to_path_buf()], &[]).unwrap();
        assert!(errors.iter().any(|e| e.contains("writable")));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (plugins, errors) = load_all(&[dir.path().to_path_buf()], &[]).unwrap();
        assert!(errors.is_empty());
        assert!(plugins.iter().any(|p| p.manifest.id == "x"));
    }
}
