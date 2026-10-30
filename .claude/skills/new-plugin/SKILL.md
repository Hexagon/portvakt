---
name: new-plugin
description: Add or update a portvakt plugin so a program (web server, database, daemon, CLI tool…) is auto-detected and manageable from the UI. Use when asked to "support X", "add a plugin for X", or fix detection/config handling for an application.
---

# Add a portvakt plugin

1. Read `docs/PLUGINS.md` fully, and the plugin rules in `AGENTS.md`.
2. Pick the closest existing plugin in `plugins/` as a model
   (`nginx.toml` service+config, `docker.toml` JSON table views, `systemd.toml` column tables + params).
3. Research the program: binary names, systemd unit names on Debian/Ubuntu vs RHEL/Fedora vs Arch,
   config file locations, the config-test command, log locations, and any JSON/machine-readable output flags.
4. If the program is installed here, start from a probe:
   `cargo run -q -- plugin new <binary> --id <id> > plugins/<id>.toml` and refine it.
   Otherwise write `plugins/<id>.toml` by hand.
5. Make it safe: argv only (no shells/interpreters), tight param patterns, `privileged` only when needed,
   `validate` + `after_save` on writable configs, `confirm`/`danger` on destructive actions,
   file globs that cannot reach secrets.
6. Verify:
   - `cargo run -q -- plugin validate --detect plugins/<id>.toml`
   - `cargo run -q -- plugin show <id>`
   - `cargo test`
7. Go through the review checklist at the end of `docs/PLUGINS.md`.
8. Summarize what you verified and what you could not (e.g. program not installed → detection untested).
