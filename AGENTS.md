# AGENTS.md — instructions for coding agents

portvakt is a secure, plugin-driven web admin for Linux servers, written in Rust,
with a VS Code-style browser UI. **Security is priority one**: it is meant to be
exposed to the internet. Read this whole file before changing anything.

## The most common task: add support for a program

Almost always this means **one new TOML file in `plugins/`**, no Rust.

1. Read [`docs/PLUGINS.md`](docs/PLUGINS.md) (the complete manifest reference).
2. Look at a similar existing plugin in `plugins/` and copy its structure:
   - service + config files + validation: `nginx.toml`, `openssh.toml`
   - table views from JSON output with row actions: `docker.toml`
   - table views from column output, parameterised actions: `systemd.toml`
3. If the program is installed where you run, draft from reality:
   `cargo run -q -- plugin new <binary> --id <id> > plugins/<id>.toml`
   Then edit: fill TODOs, tighten the version regex, add `validate` for config
   files, add useful actions, remove anything you can't justify.
4. Research the program's real facts (unit names per distro, config paths,
   config-test command, machine-readable output flags). Do not guess paths.
5. Validate: `cargo run -q -- plugin validate --detect plugins/<id>.toml`
6. Inspect: `cargo run -q -- plugin show <id>` (shows actions/files/logs found on this host).
7. `cargo test` (a test asserts that every built-in plugin is valid).
8. Walk the **Review checklist** at the end of `docs/PLUGINS.md` and the
   security rules in it. Report honestly what you could and couldn't test
   (e.g. "schema validated; detection not tested, program not installed").

Rules you must not break in a plugin (details in `docs/PLUGINS.md`):
no shell or interpreter in any argv (`sh -c`, `bash -c`, `python -c`, `env`,
`xargs`, …); tight anchored-by-default `pattern` for every param (never `.*`);
`privileged` only when needed; `validate` on writable configs that have a
checker; `confirm`/`danger` on destructive actions; file globs never match
secrets or unrelated files.

Only write a **native** plugin (Rust, `src/plugins/native.rs`) when a command
can't do it: reading `/proc`, sampling metrics, sending signals. Native hooks
must re-validate everything coming from the browser and must not spawn programs.

## Repository map

```
src/
  main.rs            CLI: serve, init, user, plugin {validate,list,show,new}, sudoers
  config.rs          portvakt.toml schema + hard safety checks (refuses unsafe setups)
  auth.rs            Argon2id, TOTP, sessions, CSRF tokens, login rate limiting
  web.rs             axum router, security headers, Authed/Admin extractors, API handlers
  terminal.rs        PTY over WebSocket (admin only)
  exec.rs            THE ONLY place that runs external programs (argv, safe PATH, env cleared, timeouts)
  audit.rs           JSON-lines audit log
  plugins/
    manifest.rs      plugin schema + validation (the plugin API; keep docs/PLUGINS.md in sync)
    detect.rs        detection rules
    runtime.rs       actions, service control, files (backup/validate/rollback), logs, views
    mod.rs           loading (native → built-in → external dirs), trust checks, registry
    native.rs        native plugins: System, Task Manager, System Monitor, Terminal
    native/*.toml    their manifests
plugins/*.toml       built-in declarative plugins (embedded at build time)
web/                 UI: index.html, app.css, app.js (plain ES module, no build), vendor/xterm
docs/                PLUGINS.md, SECURITY.md
site/                product/docs website (GitHub Pages) + install.sh
```

## Build, run, test

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings      # keep it clean

# Dev server on http://127.0.0.1:18443 with a throwaway config
mkdir -p /tmp/pv && echo 'dev-password-123' | cargo run -q -- -c /tmp/pv/portvakt.toml \
  init --bind 127.0.0.1:18443 --data-dir /tmp/pv/data --password-stdin
cargo run -q -- -c /tmp/pv/portvakt.toml serve
```

In debug builds the UI files in `web/` are read from disk, so UI edits only
need a browser reload. Release builds embed them.

UI end-to-end test (Playwright is preinstalled in many agent sandboxes), against a
running dev server: `PV_PASS=dev-password-123 node tests/e2e.mjs`. It covers login,
CSRF, file editing with validation rollback (if nginx is installed), task manager,
monitor, terminal, audit log and the palette. Five failed logins lock the account
for 15 minutes (that's the rate limiter working) — restart the dev server to reset.

Website: `sh site/_build/build.sh /tmp/site` (needs pandoc) builds `site/` + `docs/*.md`
into a static site; `.github/workflows/pages.yml` publishes it on push to main.

Release: bump `version` in `Cargo.toml`, commit, then push a tag `vX.Y.Z`.
`.github/workflows/release.yml` builds static musl binaries (x86_64, aarch64) and
publishes them with checksums; `site/install.sh` downloads from the latest release.

## Security invariants (do not weaken)

If a change touches any of these, call it out explicitly in your summary.

- External programs run **only** through `exec::prepare` + `exec::run`. Never
  `std::process::Command`/`tokio::process::Command` elsewhere, never a shell.
- Every API handler takes `Authed` or `Admin`. Anything that changes state or
  reveals file contents/logs/command output is `Admin`.
- Non-GET requests are protected by Origin + CSRF header in `Authed`. Don't add
  GET handlers that change state.
- New plugin capabilities must refuse to act on undetected plugins (`managed()` in `web.rs`).
- File access only through `runtime::read_file`/`write_file` (declared globs only).
- Startup must keep refusing: non-loopback without TLS/proxy, config readable
  by others, untrusted plugin dirs.
- UI: never `innerHTML`/`insertAdjacentHTML`/`eval`; build DOM with `h()`/`textContent`.
  No inline scripts or handlers, no CDNs — the CSP forbids them and must stay strict.
- Plugins never send code to the browser; extend view *types* in `app.js` instead.
- Everything security-relevant is written to the audit log.
- Add a test for every new validation rule or guard (see existing tests in each module).

## Conventions

- Rust 2024 edition, `anyhow` for errors, no `unwrap()` on input-derived data.
- Comments explain *why*; keep them short and match the surrounding density.
- UI: vanilla JS, colours via CSS variables in `app.css` (dark + light themes).
- Keep `docs/PLUGINS.md`, `docs/SECURITY.md` and the site in sync with behaviour.
- Commit messages: imperative summary line, body explains why.
