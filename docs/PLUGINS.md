# Writing portvakt plugins

A plugin teaches portvakt about one program: how to **detect** it, how to
**control** it, which **config files** it may edit, where its **logs** are, and
optionally which **views** (tables) to show. Most plugins are a single TOML
file with no code at all.

This document is the complete reference. It is written for both humans and
coding agents. If you are an agent, also read [`AGENTS.md`](../AGENTS.md).

- [Quick start](#quick-start)
- [How plugins are loaded](#how-plugins-are-loaded)
- [Manifest reference](#manifest-reference)
- [Recipes](#recipes)
- [Security rules for plugin authors](#security-rules-for-plugin-authors)
- [Testing a plugin](#testing-a-plugin)
- [Native (Rust) plugins](#native-rust-plugins)
- [Review checklist](#review-checklist)

---

## Quick start

```sh
# 1. Probe the host and get a draft manifest
portvakt plugin new redis-server --id redis > plugins/redis.toml

# 2. Edit it (see the reference below), then validate and test detection
portvakt plugin validate --detect plugins/redis.toml

# 3. See exactly what the UI will offer on this host
portvakt -c /etc/portvakt/portvakt.toml plugin show redis
```

A minimal but useful plugin:

```toml
id = "redis"
name = "Redis"
description = "In-memory key/value store."
category = "Databases"
icon = "database"

[detect]
any = [{ binary = "redis-server" }, { systemd_unit = "redis-server.service" }]

[version]
command = ["redis-server", "--version"]
regex = 'v=(\S+)'

[service]
systemd = "redis-server.service"
actions = ["start", "stop", "restart"]

[[files]]
path = "/etc/redis/redis.conf"
language = "ini"
after_save = "restart"

[[logs]]
label = "Journal"
journal = "redis-server.service"
```

That is all it takes for portvakt to find Redis, show its version and service
state, start/stop/restart it, edit its config (with backup) and tail its journal.

---

## How plugins are loaded

| Source | Location | Notes |
|---|---|---|
| Native | `src/plugins/native/*.toml` + Rust in `src/plugins/native.rs` | Compiled in. For things a command can't do (reading `/proc`, metrics, signals). |
| Built-in | `plugins/*.toml` in this repo | Embedded into the binary at build time. |
| External | every directory in `plugins.dirs` in `portvakt.toml` | Loaded at startup. Same id as a built-in **overrides** it. |

Rules enforced by the loader:

- The file name must be `<id>.toml`.
- External plugin directories **and** files must be owned by root (or the user
  portvakt runs as) and must not be group/world-writable. A plugin can make
  portvakt run commands, so it is protected like the binary itself. An unsafe
  directory aborts startup; an unsafe file is skipped with an error.
- An invalid manifest is skipped and reported (log + Audit panel in the UI);
  it never prevents the server from starting.
- `plugins.disabled = ["id", ...]` turns plugins off.
- Plugins are only *acted on* when detected. Actions, files, logs and views of
  an undetected plugin are refused by the server.

---

## Manifest reference

Unknown keys are an error (typos are caught). All paths must be absolute.

### Top level

| Key | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | `[a-z0-9][a-z0-9-]*`, max 63 chars. Also the file name. |
| `name` | string | yes | Display name. |
| `description` | string | | One line. Shown in tooltips and the overview. |
| `category` | string | | Sidebar group. Use an existing one if it fits: `System`, `Web servers`, `Databases`, `Containers`, `Security`, `Monitoring`, `Mail`, `Other` (default). |
| `icon` | string | | One of `app` (default), `globe`, `database`, `server`, `box`, `lock`, `terminal`, `pulse`, `graph`, `shield`, `cog`, `file`, `log`, `table`, `bolt`. |

### `[detect]` — is it installed?

```toml
[detect]
any = [ rule, rule, ... ]   # at least one must match (if non-empty)
all = [ rule, rule, ... ]   # every one must match
```

At least one of `any`/`all` must have a rule. Each **rule sets exactly one** of:

| Rule | Matches when | Example |
|---|---|---|
| `binary` | executable found in the safe PATH (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) or at an absolute path | `{ binary = "nginx" }` |
| `path` | a file/dir exists; glob allowed | `{ path = "/etc/php/*/fpm/php-fpm.conf" }` |
| `systemd_unit` | the unit file exists in a systemd unit dir | `{ systemd_unit = "nginx.service" }` |
| `process` | a process with this exact name (`/proc/<pid>/comm`, max 15 chars) runs | `{ process = "mysqld" }` |
| `port` | something listens on this TCP port | `{ port = 6379 }` |
| `command` (+ optional `regex`) | command exits 0 (and output matches) | `{ command = ["pg_lsclusters", "-h"], regex = '\d+\s+main' }` |

Prefer cheap rules (`binary`, `path`, `systemd_unit`) over `command`. Use
`any` for "installed in any of these ways", `all` for extra requirements.
Detection runs at startup, every 10 minutes and on *Rescan*.

### `[version]` — optional

```toml
[version]
command = ["nginx", "-v"]
regex = 'nginx/(\S+)'     # first capture group = version
```

The regex is applied to stdout followed by stderr (many tools print their
version on stderr, and some exit non-zero for `--version`; both are fine).

### `[service]` — optional systemd integration

```toml
[service]
systemd = "nginx.service"
actions = ["start", "stop", "restart", "reload"]   # default: start, stop, restart
```

Adds the service state to the overview/sidebar and the chosen lifecycle
actions (`start`, `stop`, `restart`, `reload`, `enable`, `disable`). They run
`systemctl <verb> <unit>` as privileged commands. `stop`, `restart` and
`disable` ask for confirmation. Only list `reload` if the unit supports it.

### `[[info]]` — key/value rows in the overview

```toml
[[info]]
label = "Engine"
command = ["docker", "info", "--format", "{{.ServerVersion}}"]
regex = '(\S+)'          # optional: first group (or whole match) is shown
privileged = false       # optional
```

Without `regex`, the trimmed output (max 20 lines) is shown. Keep info probes
fast and read-only; they run every time the overview opens (10 s timeout).

### `[[actions]]` — buttons

```toml
[[actions]]
id = "test-config"                 # [a-z0-9-]+, unique incl. service actions
label = "Test configuration"
description = "nginx -t"           # optional, tooltip and confirm text
command = ["nginx", "-t"]          # argv, never a shell
privileged = true                  # needs root (uses sudo -n when use_sudo = true)
confirm = false                    # ask before running
timeout = 30                       # seconds, 1..=600
```

**Parameters.** Placeholders `{name}` in `command` are replaced by validated
user input:

```toml
[[actions]]
id = "unit-status"
label = "Unit status"
command = ["systemctl", "status", "--no-pager", "{unit}"]
params = [{ name = "unit", label = "Unit", pattern = '[A-Za-z0-9@._:\-]+\.service', default = "nginx.service" }]
```

| Param key | Description |
|---|---|
| `name` | `[a-z_][a-z0-9_]*`. `file` is reserved. |
| `label` | Shown in the UI. |
| `pattern` | Regex the **whole** value must match (it is wrapped in `^(?:…)$` for you). Make it as tight as possible. |
| `default` | Optional; must match `pattern`. |
| `allow_dash` | Default `false`: values starting with `-` are rejected so input can't become an option. |

The program (`command[0]`) can never be a placeholder. Values are substituted
inside single argv elements and never pass through a shell, so `;`, `$()`,
spaces etc. have no special meaning — but your `pattern` is still the main
defence, e.g. against path traversal. Never use `.*` or `.+`.

The output (stdout, stderr, exit code, duration) is shown in the Output panel.

### `[[files]]` — editable configuration

```toml
[[files]]
path = "/etc/nginx/sites-available/*"   # glob → one entry per existing file
language = "nginx"                      # editor hint
readonly = false
validate = ["nginx", "-t"]              # run AFTER writing; non-zero exit → previous content restored
validate_privileged = true
after_save = "reload"                   # action id to run after a successful save (no params)
```

How saving works (`src/plugins/runtime.rs`):

1. The file must be one of the paths the globs expand to *right now*.
2. Optimistic locking: if the file changed on disk since it was opened, the save is refused.
3. The old content is backed up to `<data_dir>/backups/<plugin>/`.
4. The new content is written atomically (temp file + rename), keeping mode and owner.
5. `validate` runs with `{file}` replaced by the real path. On failure the old
   content is restored and the validator output is shown.
6. `after_save` runs.

Files must be UTF-8 and at most 2 MiB. Symlinks are followed only if owned by
root or portvakt's user. Use `readonly = true` for files people should see
but not edit from a browser (e.g. `/etc/fstab`).

**Always provide `validate` when the program has a config check** (`nginx -t`,
`sshd -t`, `apachectl configtest`, `named-checkconf {file}`, `haproxy -c -f {file}`,
`visudo -cf {file}`, `dockerd --validate --config-file {file}`, `caddy validate --config {file}`).

### `[[logs]]`

```toml
[[logs]]
label = "Error log"
path = "/var/log/nginx/error.log"     # tail of the newest matching file (last 256 KiB)

[[logs]]
label = "Journal"
journal = "nginx.service"             # journalctl -u <unit> -n 500 (privileged)
```

Exactly one of `path` / `journal`.

### `[[views]]` — tables built from command output

Views open as editor tabs (or in the bottom panel with `location = "panel"`).
Declarative plugins can only define **table** views backed by a `command`.

```toml
[[views]]
id = "containers"
label = "Containers"
type = "table"
refresh = 5                       # seconds, 0 = manual (min 2)
activity = false                  # also put a shortcut in the activity bar
command = ["docker", "ps", "--all", "--format", "{{json .}}"]
privileged = true
format = "json-lines"             # json | json-lines | columns
key = "ID"                        # unique row field, required for row_actions
columns = [
  { key = "Names", label = "Name" },
  { key = "State", label = "State", format = "status" },   # text | number | bytes | percent | status
]
row_actions = [
  { action = "container-restart", params = { id = "ID" } },   # action param ← row field
  { action = "container-stop", params = { id = "ID" }, danger = true, label = "Stop" },
]
```

Formats:

- `json` — output is a JSON array of objects.
- `json-lines` — one JSON object per line (`docker … --format '{{json .}}'`, `ip -j`, …).
- `columns` — whitespace separated; values are assigned to `columns` in order,
  the **last column takes the rest of the line**. `skip_lines = 1` skips a header.

Row actions call a normal `[[actions]]` entry of the same plugin. Every param
of that action must be mapped (or have a default), and mapped values go
through the same `pattern` validation as typed input — a row is just another
form of untrusted input. If `columns` is omitted, all fields are shown.

Prefer machine-readable output (`--format json`, `-j`, `--output=json`) over
parsing columns whenever the program offers it.

---

## Recipes

**Distro differences.** Put every variant in `detect.any`, and use globs:

```toml
[detect]
any = [
  { systemd_unit = "apache2.service" },   # Debian/Ubuntu
  { systemd_unit = "httpd.service" },     # RHEL/Fedora/Arch
  { binary = "apache2" }, { binary = "httpd" },
]
```

`[service]` takes one unit name. If distros differ, prefer the name that has an
alias on the other (e.g. `sshd.service` exists as an alias of `ssh.service` on
Debian). If there is no alias, write two small plugins (`apache2`, `httpd`)
whose `detect` rules exclude each other.

**Versioned paths** (`/etc/php/8.3/fpm/…`): use globs in `path`, `files` and `logs`.

**A program without systemd** (supervisor, runit, docker-compose): skip
`[service]` and add explicit `[[actions]]`.

**Commands that need root.** Mark `privileged = true`. Read-only probes that
work unprivileged should stay unprivileged. Run `portvakt sudoers` to see the
exact sudoers lines your plugin needs in sudo mode.

**Dangerous actions** (delete, prune, drop, stop, kill): `confirm = true`, and
`danger = true` on row actions.

**Reload after save:** `after_save = "reload"` if the service supports reload,
otherwise `"restart"`.

---

## Security rules for plugin authors

These are not style preferences; reviews reject plugins that break them.

1. **argv only.** Never `["sh", "-c", "…"]`, `bash -c`, `env`, `xargs`, `find -exec`,
   `awk 'system(…)'` or anything else that re-introduces a shell or runs
   arbitrary commands. If you need a pipeline, you need a native plugin.
2. **No interpreters with code arguments** (`python -c`, `perl -e`, `node -e`, `php -r`).
3. **Tight `pattern`s.** No `.*`, `.+`, `\S+` for anything that ends up in a path
   or unit name. Whitelist characters. Don't set `allow_dash` unless the value
   must be negative/an option.
4. **Least privilege.** `privileged = true` only where root is actually required.
5. **Validate configs.** Every writable `[[files]]` of a program with a config
   checker gets `validate`.
6. **Narrow file globs.** Only real config files of that program — never
   `/etc/*`, home directories, keys (`*.key`, `*.pem`), `/etc/shadow`, etc.
   Secrets files should be absent or `readonly`.
7. **No network fetches** from actions (`curl | …`, `wget`, package installs).
   Installing software is out of scope for plugins.
8. **Destructive = confirm.**

The server enforces a lot of this (no shell, cleared env, fixed PATH, timeouts,
output caps, path allow-list, param anchoring, option-injection guard, audit
log), but the manifest is still the security boundary for *what* may run.

---

## Testing a plugin

```sh
cargo build
./target/debug/portvakt plugin validate --detect plugins/<id>.toml   # schema + detection
./target/debug/portvakt plugin show <id>                             # what the UI will offer
cargo test                                                           # includes "all built-in plugins are valid"
```

For an end-to-end check, run a dev server (see `AGENTS.md`) and open the app in
the UI: run each action, open each file, save without changes, save a broken
config and confirm it is rolled back, open each log and view.

If the program isn't installed where you are, you can still validate the
schema (`validate` without `--detect`). Do not mark detection as tested then.

---

## Native (Rust) plugins

Use these only when a declarative plugin can't do the job: reading `/proc` or
`/sys` directly, sampling over time, sending signals, or anything that would
otherwise need a shell pipeline.

1. Add `src/plugins/native/<id>.toml` — a normal manifest. Its views may omit
   `command` and may use `type = "metrics"` (or `"terminal"`).
2. Implement `NativePlugin` in `src/plugins/native.rs`:

   ```rust
   pub trait NativePlugin: Send + Sync {
       fn manifest(&self) -> &'static str;                       // include_str!("native/<id>.toml")
       fn info(&self) -> Vec<(String, String)> { vec![] }        // extra overview rows
       fn view_data(&self, view: &str) -> Result<Value>;         // {"rows":[…]} or {"series":[…]}
       fn view_action(&self, view: &str, action: &str, row: &Value) -> Result<String>;
   }
   ```

3. Register it in `native::all()` and add tests next to the others.

Hooks run on a blocking thread; keep them fast. `view_action` receives the row
**from the browser**: re-validate every field (see `Processes::view_action`,
which checks the pid range, refuses pid 1 and itself, and verifies the start
time to defeat PID reuse). Never run external programs from native hooks —
that's what declarative actions are for.

Metrics views return:

```json
{ "series": [ { "id": "cpu", "label": "CPU", "unit": "%", "max": 100, "points": [[1730246400, 12.5], …] } ] }
```

`unit` `"%"` and `"B/s"` get special formatting; `max: null` auto-scales.

---

## Review checklist

- [ ] `id` matches the file name; `name`, `description`, `category`, `icon` set.
- [ ] Detection covers the common distros and doesn't false-positive on unrelated packages.
- [ ] `portvakt plugin validate --detect` passes; `plugin show` output looks right.
- [ ] No shell/interpreter in any argv; params have tight patterns.
- [ ] Only commands that need root are `privileged`.
- [ ] Writable config files have `validate` (if the program has a checker) and a sensible `after_save`.
- [ ] Destructive actions have `confirm = true` / `danger = true`.
- [ ] File globs cannot match secrets or unrelated files.
- [ ] `cargo test` passes.
