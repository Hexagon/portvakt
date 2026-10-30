# Security model

portvakt is designed to be safe to expose to the internet. Security wins every
trade-off against convenience. This document lists what is protected, how, and
what you must do when deploying.

## What an attacker gets if they win

An admin session can run plugin actions, edit managed config files and — if the
terminal is enabled — open a shell as the user portvakt runs as. So the goals are:

1. Nobody without valid credentials (and TOTP) gets a session.
2. A session cannot be hijacked or abused cross-site.
3. A logged-in user can only do what plugins explicitly allow — except via the
   terminal, which is a deliberate escape hatch you can turn off.
4. Everything security-relevant is audited.

## Controls

### Transport
- Refuses to listen on a non-loopback address without TLS, unless
  `behind_proxy = true` (with explicit `trusted_proxies`).
- Built-in TLS via rustls (`tls_cert`/`tls_key`, or `portvakt init --self-signed`).
- HSTS whenever HTTPS is in use.

### Authentication
- Argon2id password hashes (min 12 characters); unknown users still run a full
  hash verification so timing does not reveal valid usernames.
- Optional TOTP (RFC 6238, ±30 s) per user; `require_totp_for_admins = true`
  makes it mandatory (startup fails otherwise). **Use it when exposed to the internet.**
- Login rate limiting per source IP **and** per username (default 5 failures /
  15 min), so distributed guessing against one account is slowed too.
- `X-Forwarded-For` is only honoured from `trusted_proxies`.

### Sessions
- 256-bit random token in an `HttpOnly`, `SameSite=Strict` cookie; `Secure` and
  the `__Host-` prefix whenever HTTPS is in use.
- Only the SHA-256 of tokens is held server-side (in memory; a restart logs everyone out).
- Idle timeout (30 min) and absolute lifetime (12 h). Logout and expiry also
  close open terminals.

### Cross-site protection
- Every state-changing request needs the per-session CSRF token header **and** a
  matching `Origin` header. The terminal WebSocket checks `Origin` on upgrade and
  requires the CSRF token as its first message.
- Set `public_origin` when exposed; otherwise the expected origin is derived from `Host`.

### Browser hardening
- Strict CSP: `default-src 'none'; script-src 'self'` — no inline script, no
  eval, no third-party origins. All assets (including xterm.js) are embedded in
  the binary. `style-src` allows `'unsafe-inline'` because xterm.js injects style
  elements; no script can be injected through styles under this policy.
- `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`,
  COOP/CORP same-origin, restrictive Permissions-Policy, `Cache-Control: no-store` on the API.
- The UI builds all DOM with `textContent`; data never reaches `innerHTML`.
- Plugins never ship JavaScript to the browser. They declare data-driven views.

### Authorization
- Roles: `admin` (everything) and `viewer` (sees which apps exist and their
  state; no info probes, files, logs, views, actions or terminal).
- Nothing is done for plugins whose application is not detected.

### Command execution (`src/exec.rs`)
- argv only — there is no code path that invokes a shell for plugins.
- Programs are resolved in a fixed root-owned PATH, never the caller's.
- Environment is cleared (only `PATH`, `LANG`, `HOME`, pager vars).
- stdin closed, 1 MiB output cap, timeouts kill the process.
- Parameters must fully match a per-param regex; values starting with `-` are
  rejected by default (option injection).

### Files
- Only files matching a plugin's declared globs at request time.
- UTF-8 only, ≤ 2 MiB, optimistic locking against concurrent edits.
- Backup before every write; atomic replace preserving owner and mode.
- Validation command after write, automatic rollback on failure.
- Symlinks are followed only when owned by root or portvakt's user.

### Plugins
- External plugin dirs/files must be owned by root/portvakt's user and not
  group/world-writable, or they are not loaded.
- Strict schema (`deny_unknown_fields`), validated at load and in CI.

### Config
- `portvakt.toml` holds hashes and TOTP secrets; portvakt refuses to start if
  it is accessible by other users. Written with mode 0600.

### Audit
- Logins (ok/failed/rate-limited), logouts, CSRF/Origin rejections, every
  action (with params and exit code), file reads/writes (with backup path),
  view actions and terminal open/close are appended to `<data_dir>/audit.log`
  (JSON lines, 0600) and visible in the UI's Audit panel.
- Keystrokes in the terminal are **not** recorded.

## Deployment recommendations

1. **Use TOTP** for every account, and `require_totp_for_admins = true`.
2. **TLS**: either a reverse proxy with a real certificate (Caddy/nginx +
   `behind_proxy = true`, `trusted_proxies = ["127.0.0.1"]`,
   `public_origin = "https://admin.example.com"`), or built-in TLS with a real
   certificate. A self-signed certificate is fine for a first start, not for daily use.
3. **Restrict who can reach it**: firewall to known IPs or put it behind a VPN
   (WireGuard/Tailscale) if you can. Being internet-safe doesn't mean it must be public.
4. **Run unprivileged with sudo** (recommended):
   - create a `portvakt` system user,
   - set `security.use_sudo = true`,
   - install the allow-list from `portvakt sudoers --user portvakt | sudo tee /etc/sudoers.d/portvakt`
     (review it; check with `visudo -cf`),
   - grant write access to the config files you want editable via group/ACL,
   - the web terminal then is a shell for the unprivileged `portvakt` user.
   Running as root works and is simpler, but then the terminal is a root shell.
5. **Disable the terminal** if you don't need it: `terminal.enabled = false`
   or `plugins.disabled = ["terminal"]`.
6. Keep `audit.log` shipped somewhere you can't tamper with from the box.

## Reporting vulnerabilities

Please report privately via GitHub Security Advisories on
`Hexagon/portvakt` rather than in a public issue.
