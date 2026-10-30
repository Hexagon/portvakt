# portvakt

**A secure, plugin-driven web admin for Linux servers.** One small Rust binary
gives you a VS Code-style interface in the browser that finds what's installed
on the machine and lets you manage it: services, config files (with validation
and automatic rollback), logs, live system metrics, processes and a terminal.

> *Portvakt* is Swedish for gatekeeper.

- **Security first** — built to be exposed to the internet: TLS-or-refuse,
  Argon2id + TOTP, strict CSP, CSRF + Origin checks, no shell anywhere, audit log.
  See [docs/SECURITY.md](docs/SECURITY.md).
- **Auto-detection** — plugins describe how to recognise a program; portvakt
  scans the host and shows only what's there.
- **Plugins are TOML** — teaching portvakt about a new program is usually one
  file with no code. `portvakt plugin new <binary>` drafts it from the live
  system. See [docs/PLUGINS.md](docs/PLUGINS.md).
- **Familiar UI** — activity bar, explorer, tabs, command palette
  (<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>), bottom panel with terminal,
  output and audit log, dark and light themes.

Built-in plugins: System overview, Task Manager, System Monitor, Terminal,
systemd services, Docker, nginx, OpenSSH.

## Install

```sh
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh
```

The installer downloads the release binary, creates `/etc/portvakt/portvakt.toml`
with an admin user, and installs a systemd service listening on
`127.0.0.1:8443`. Update later with:

```sh
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- update
```

Options (`--help` for all): `--bind 0.0.0.0:8443 --self-signed`, `--behind-proxy`,
`--public-origin https://admin.example.com`, `--totp`, `--sudo-mode`, `--version vX.Y.Z`.

## Build from source

```sh
cargo build --release
sudo install -m 755 target/release/portvakt /usr/local/bin/
sudo portvakt init --totp             # prompts for the admin password
sudo portvakt serve
```

Then open <http://127.0.0.1:8443> (tunnel with `ssh -L 8443:127.0.0.1:8443 server`),
or follow the deployment advice in [docs/SECURITY.md](docs/SECURITY.md) to expose it.

## CLI

```
portvakt serve                         run the server
portvakt init [--self-signed] [--totp] create a config with an admin user
portvakt user add|passwd|totp|remove   manage users
portvakt plugin list                   what's detected on this host
portvakt plugin show <id>              what a plugin exposes here
portvakt plugin new <binary>           draft a plugin manifest from the live system
portvakt plugin validate <files…>      check manifests (CI-friendly)
portvakt sudoers                       sudoers allow-list for running unprivileged
```

## Writing plugins / contributing with an agent

- Plugin reference: [docs/PLUGINS.md](docs/PLUGINS.md)
- Agent instructions: [AGENTS.md](AGENTS.md)
- Template: [docs/plugin-template.toml](docs/plugin-template.toml)

## License

MIT
