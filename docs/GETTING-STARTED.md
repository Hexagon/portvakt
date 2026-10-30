# Getting started

portvakt is a single binary that runs as a systemd service on the server you
want to manage. You reach it with a browser.

## Install

```sh
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh
```

The installer:

1. downloads the static binary for your CPU (x86_64 or aarch64) from GitHub
   Releases, verifies its SHA-256 checksum and installs it to `/usr/local/bin/portvakt`;
2. asks for an admin password (or generates one if there is no terminal) and
   writes `/etc/portvakt/portvakt.toml` (mode 0600);
3. installs and starts `portvakt.service`, listening on `127.0.0.1:8443`.

It only listens locally by default. Open it through an SSH tunnel:

```sh
ssh -L 8443:127.0.0.1:8443 you@your-server
```

and browse to <http://localhost:8443>.

### Installer options

| Option | Effect |
|---|---|
| `--bind 0.0.0.0:8443 --self-signed --san admin.example.com` | Listen publicly with a generated TLS certificate. |
| `--behind-proxy --public-origin https://admin.example.com` | A reverse proxy on the same host terminates TLS. |
| `--totp` | Enable two-factor authentication for the admin and print the `otpauth://` URI. |
| `--sudo-mode` | Run as an unprivileged `portvakt` user with a generated sudoers allow-list. |
| `--admin <name>` / `--admin-password <pw>` | Admin account (password is prompted otherwise). |
| `--version v0.1.0` | Install a specific release. |
| `--from-source` | Build with `cargo` instead of downloading. |

Pass options after `sh -s --`:

```sh
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- --totp --sudo-mode
```

Non-secret settings are saved in `/etc/portvakt/install.conf` and reused by `update`.

## Update and uninstall

```sh
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- update
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- uninstall          # keeps config + data
curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- uninstall --purge
```

## Exposing it to the internet

Read the [security model](SECURITY.md) first. The short version:

- Turn on TOTP for every account (`portvakt user totp <name>`) and set
  `require_totp_for_admins = true`.
- Use a real certificate. The easiest way is a reverse proxy such as Caddy:

  ```
  admin.example.com {
      reverse_proxy 127.0.0.1:8443
  }
  ```

  with this in `/etc/portvakt/portvakt.toml`:

  ```toml
  [server]
  bind = "127.0.0.1:8443"
  behind_proxy = true
  trusted_proxies = ["127.0.0.1", "::1"]
  public_origin = "https://admin.example.com"
  ```

- If you can, also limit who can reach it (firewall allow-list or VPN).

portvakt refuses to start on a public address without TLS or a proxy configuration.

## Using the interface

| | |
|---|---|
| Sidebar | Detected applications grouped by category. The dot shows the systemd state. **+** shows plugins that were not detected. |
| App tab | Version, service state, actions, configuration files, logs and views. |
| Editor | <kbd>Ctrl</kbd>+<kbd>S</kbd> saves. The file is backed up, validated and rolled back if the check fails. |
| Panel | Output of actions, the terminal and the audit log. <kbd>Ctrl</kbd>+<kbd>`</kbd> toggles it. |
| Command palette | <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> for commands, <kbd>Ctrl</kbd>+<kbd>P</kbd> for apps and files. |

## Users

```sh
sudo portvakt user list
sudo portvakt user add alice --role viewer     # admin or viewer
sudo portvakt user passwd alice
sudo portvakt user totp alice                  # enable or rotate TOTP
sudo portvakt user remove alice
sudo systemctl restart portvakt                # apply
```

## Configuration reference

`/etc/portvakt/portvakt.toml`:

```toml
[server]
bind = "127.0.0.1:8443"
# tls_cert = "/etc/portvakt/cert.pem"
# tls_key = "/etc/portvakt/key.pem"
behind_proxy = false
trusted_proxies = []
# public_origin = "https://admin.example.com"
data_dir = "/var/lib/portvakt"          # audit.log and file backups

[security]
session_idle_minutes = 30
session_absolute_hours = 12
max_login_failures = 5
lockout_minutes = 15
require_totp_for_admins = false
use_sudo = false                        # prefix privileged commands with sudo -n

[terminal]
enabled = true
shell = "/bin/bash"

[plugins]
dirs = []                               # extra directories with *.toml plugins
disabled = []                           # plugin ids to turn off, e.g. ["terminal"]

[[users]]
name = "admin"
password_hash = "$argon2id$..."
role = "admin"
# totp_secret = "BASE32..."
```

## Adding support for more software

See [Writing plugins](PLUGINS.md). Usually it's one TOML file, and
`portvakt plugin new <binary>` writes the first draft for you. Put your own
plugins in a directory listed in `plugins.dirs` (owned by root, not writable by
others), or contribute them to the repository.
