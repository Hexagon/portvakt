#!/bin/sh
# portvakt installer — https://hexagon.github.io/portvakt/install.sh
# Usage: curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh
#        curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- update
#        curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- --bind 0.0.0.0:8443 --self-signed --totp
#
# NOTE: This script is POSIX sh-compatible. It is piped via `curl | sh` which
# bypasses the shebang, so it must work under /bin/sh (dash, bash, busybox sh).
# No bashisms allowed: no [[, no &>, no =~, no == inside [ ].
set -eu

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REPO="Hexagon/portvakt"
BIN="/usr/local/bin/portvakt"
CONF_DIR="/etc/portvakt"
CONF="${CONF_DIR}/portvakt.toml"
INSTALL_CONF="${CONF_DIR}/install.conf"
DATA_DIR="/var/lib/portvakt"
UNIT="/etc/systemd/system/portvakt.service"
SVC_USER="portvakt"
DEFAULT_BIND="127.0.0.1:8443"

say()  { echo "==> $*"; }
warn() { echo "==> WARNING: $*" >&2; }
die()  { echo "==> ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
show_help() {
    cat <<EOF
portvakt installer — https://hexagon.github.io/portvakt/install.sh

Usage:
  curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh
  curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- [command] [options]

Commands:
  install                Install portvakt (default)
  update                 Replace the binary with the latest release, keep config, restart
  uninstall              Remove binary and service (keeps ${CONF_DIR} and ${DATA_DIR})
  uninstall --purge      Also remove config, audit log and backups

Options (install):
  --version <tag>        Release tag to install (default: latest)
  --bind <addr:port>     Listen address (default: ${DEFAULT_BIND})
  --self-signed          Generate a self-signed TLS certificate (needed for a public --bind)
  --san <name>           Hostname/IP for the self-signed certificate (repeatable)
  --behind-proxy         A TLS reverse proxy on this host forwards to portvakt
  --public-origin <url>  Public URL, e.g. https://admin.example.com (recommended when exposed)
  --admin <name>         Admin username (default: admin)
  --admin-password <pw>  Admin password (default: prompt, or generate one if no terminal)
  --totp                 Enable TOTP two-factor auth for the admin (recommended)
  --sudo-mode            Run as an unprivileged '${SVC_USER}' user with a sudoers allow-list
  --from-source          Build with cargo instead of downloading a release
  --help                 Show this help message

Notes:
  Settings are persisted in ${INSTALL_CONF} for future updates.
  A public --bind without --self-signed or --behind-proxy is refused by portvakt itself.
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
CMD="install"
VERSION=""
BIND=""
SELF_SIGNED=""
SANS=""
BEHIND_PROXY=""
PUBLIC_ORIGIN=""
ADMIN=""
ADMIN_PASSWORD=""
TOTP=""
SUDO_MODE=""
FROM_SOURCE=""
PURGE=false

need_arg() {
    if [ -z "${2:-}" ] || echo "$2" | grep -q '^--'; then
        die "$1 requires an argument"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h) show_help ;;
        install|update|uninstall) CMD="$1"; shift ;;
        --purge) PURGE=true; shift ;;
        --version) need_arg "$1" "${2:-}"; VERSION="$2"; shift 2 ;;
        --bind) need_arg "$1" "${2:-}"; BIND="$2"; shift 2 ;;
        --self-signed) SELF_SIGNED=true; shift ;;
        --san) need_arg "$1" "${2:-}"; SANS="${SANS} --san $2"; shift 2 ;;
        --behind-proxy) BEHIND_PROXY=true; shift ;;
        --public-origin) need_arg "$1" "${2:-}"; PUBLIC_ORIGIN="$2"; shift 2 ;;
        --admin) need_arg "$1" "${2:-}"; ADMIN="$2"; shift 2 ;;
        --admin-password) need_arg "$1" "${2:-}"; ADMIN_PASSWORD="$2"; shift 2 ;;
        --totp) TOTP=true; shift ;;
        --sudo-mode) SUDO_MODE=true; shift ;;
        --from-source) FROM_SOURCE=true; shift ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "please run as root, e.g.: curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh"
[ "$(uname -s)" = "Linux" ] || die "portvakt only supports Linux"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# ---------------------------------------------------------------------------
# Persisted installer settings (only non-secret values)
# ---------------------------------------------------------------------------
if [ -f "$INSTALL_CONF" ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            \#*|"") continue ;;
            bind)          [ -z "$BIND" ] && BIND="$value" ;;
            self_signed)   [ -z "$SELF_SIGNED" ] && SELF_SIGNED="$value" ;;
            behind_proxy)  [ -z "$BEHIND_PROXY" ] && BEHIND_PROXY="$value" ;;
            public_origin) [ -z "$PUBLIC_ORIGIN" ] && PUBLIC_ORIGIN="$value" ;;
            sudo_mode)     [ -z "$SUDO_MODE" ] && SUDO_MODE="$value" ;;
            from_source)   [ -z "$FROM_SOURCE" ] && FROM_SOURCE="$value" ;;
        esac
    done < "$INSTALL_CONF"
fi
[ -z "$BIND" ] && BIND="$DEFAULT_BIND"
[ -z "$ADMIN" ] && ADMIN="admin"
[ "$SELF_SIGNED" = true ] || SELF_SIGNED=false
[ "$BEHIND_PROXY" = true ] || BEHIND_PROXY=false
[ "$SUDO_MODE" = true ] || SUDO_MODE=false
[ "$FROM_SOURCE" = true ] || FROM_SOURCE=false
[ "$TOTP" = true ] || TOTP=false

save_install_conf() {
    mkdir -p "$CONF_DIR"
    cat > "$INSTALL_CONF" <<CONFEOF
# portvakt installer settings — auto-generated, edit to persist settings
bind=${BIND}
self_signed=${SELF_SIGNED}
behind_proxy=${BEHIND_PROXY}
public_origin=${PUBLIC_ORIGIN}
sudo_mode=${SUDO_MODE}
from_source=${FROM_SOURCE}
CONFEOF
    chmod 600 "$INSTALL_CONF"
}

# ---------------------------------------------------------------------------
# Download / build
# ---------------------------------------------------------------------------
detect_target() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "" ;;
    esac
}

fetch() {
    # fetch <url> <output>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

install_binary() {
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    if [ "$FROM_SOURCE" = true ]; then
        command -v cargo >/dev/null 2>&1 || die "--from-source needs cargo (https://rustup.rs)"
        command -v git >/dev/null 2>&1 || die "--from-source needs git"
        REF="${VERSION:-main}"
        say "Building portvakt ${REF} from source (this takes a few minutes)..."
        git clone -q --depth 1 --branch "$REF" "https://github.com/${REPO}.git" "$TMP/src"
        (cd "$TMP/src" && cargo build --release --locked -q)
        install -m 755 "$TMP/src/target/release/portvakt" "$BIN.new"
    else
        ARCH=$(detect_target)
        [ -n "$ARCH" ] || die "no prebuilt binary for $(uname -m); re-run with --from-source"
        ASSET="portvakt-${ARCH}-linux.tar.gz"
        if [ -n "$VERSION" ]; then
            URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
        else
            URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
        fi
        say "Downloading ${URL}"
        fetch "$URL" "$TMP/$ASSET" || die "download failed (is there a release yet? try --from-source)"
        fetch "$URL.sha256" "$TMP/$ASSET.sha256" || die "checksum download failed"
        say "Verifying checksum..."
        (cd "$TMP" && sha256sum -c "$ASSET.sha256" >/dev/null) || die "checksum mismatch — aborting"
        tar -xzf "$TMP/$ASSET" -C "$TMP"
        install -m 755 "$TMP/portvakt" "$BIN.new"
    fi
    "$BIN.new" --version >/dev/null 2>&1 || die "downloaded binary does not run on this system"
    mv -f "$BIN.new" "$BIN"
    say "Installed $("$BIN" --version)"
}

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------
write_unit() {
    if [ "$SUDO_MODE" = true ]; then
        RUN_AS="User=${SVC_USER}
Group=${SVC_USER}"
        RUN_HOME="$DATA_DIR"
    else
        RUN_AS="User=root"
        RUN_HOME="/root"
    fi
    cat > "$UNIT" <<UNITEOF
[Unit]
Description=portvakt — secure web admin
Documentation=https://hexagon.github.io/portvakt/
After=network-online.target
Wants=network-online.target

[Service]
${RUN_AS}
ExecStart=${BIN} -c ${CONF} serve
Restart=on-failure
RestartSec=3
UMask=0077
Environment=HOME=${RUN_HOME}
WorkingDirectory=${RUN_HOME}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNITEOF
    systemctl daemon-reload
}

# ---------------------------------------------------------------------------
# Sudo mode: unprivileged user + generated allow-list
# ---------------------------------------------------------------------------
setup_sudo_mode() {
    command -v sudo >/dev/null 2>&1 || die "--sudo-mode needs sudo installed"
    if ! id "$SVC_USER" >/dev/null 2>&1; then
        say "Creating system user ${SVC_USER}..."
        useradd --system --home-dir "$DATA_DIR" --shell /bin/bash "$SVC_USER"
    fi
    mkdir -p "$DATA_DIR"
    chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR" "$CONF_DIR"
    chmod 700 "$DATA_DIR"
    sed -i 's/^use_sudo = false$/use_sudo = true/' "$CONF"
    say "Generating sudoers allow-list for detected applications..."
    "$BIN" -c "$CONF" sudoers --user "$SVC_USER" > "$TMP_SUDO"
    if visudo -cf "$TMP_SUDO" >/dev/null; then
        install -m 440 "$TMP_SUDO" /etc/sudoers.d/portvakt
        say "Installed /etc/sudoers.d/portvakt — review it, and re-run 'sudo portvakt -c ${CONF} sudoers --user ${SVC_USER}' after installing new software."
    else
        warn "generated sudoers file failed validation; left at ${TMP_SUDO}"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
do_uninstall() {
    say "Stopping and removing portvakt..."
    systemctl disable --now portvakt >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIN" /etc/sudoers.d/portvakt
    systemctl daemon-reload
    if [ "$PURGE" = true ]; then
        rm -rf "$CONF_DIR" "$DATA_DIR"
        say "Removed config and data."
    else
        say "Kept ${CONF_DIR} and ${DATA_DIR} (use 'uninstall --purge' to remove)."
    fi
    exit 0
}

do_update() {
    [ -f "$CONF" ] || die "portvakt is not installed (no ${CONF}); run without 'update' first"
    install_binary
    save_install_conf
    write_unit
    systemctl restart portvakt
    say "Updated and restarted. Status: $(systemctl is-active portvakt || true)"
    exit 0
}

do_install() {
    if [ -f "$CONF" ]; then
        say "portvakt is already installed (${CONF} exists)."
        say "To update it, run:"
        say "  curl -fsSL https://hexagon.github.io/portvakt/install.sh | sudo sh -s -- update"
        exit 1
    fi
    install_binary
    save_install_conf

    GENERATED=false
    if [ -z "$ADMIN_PASSWORD" ]; then
        if [ -r /dev/tty ] && [ -w /dev/tty ]; then
            printf "==> Choose a password for '%s' (min 12 characters): " "$ADMIN" > /dev/tty
            stty -echo < /dev/tty 2>/dev/null || true
            read -r ADMIN_PASSWORD < /dev/tty || true
            stty echo < /dev/tty 2>/dev/null || true
            echo > /dev/tty
        fi
        if [ -z "$ADMIN_PASSWORD" ]; then
            ADMIN_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)
            GENERATED=true
        fi
    fi

    set -- --bind "$BIND" --data-dir "$DATA_DIR" --admin "$ADMIN" --password-stdin
    [ "$SELF_SIGNED" = true ] && set -- "$@" --self-signed
    [ -n "$PUBLIC_ORIGIN" ] && set -- "$@" --public-origin "$PUBLIC_ORIGIN"
    [ "$TOTP" = true ] && set -- "$@" --totp
    mkdir -p "$CONF_DIR"
    chmod 700 "$CONF_DIR"
    # shellcheck disable=SC2086 # SANS is intentionally word-split into --san pairs
    printf '%s\n' "$ADMIN_PASSWORD" | "$BIN" -c "$CONF" init "$@" $SANS

    if [ "$BEHIND_PROXY" = true ]; then
        sed -i 's/^behind_proxy = false$/behind_proxy = true/; s/^trusted_proxies = \[\]$/trusted_proxies = ["127.0.0.1", "::1"]/' "$CONF"
    fi
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"

    if [ "$SUDO_MODE" = true ]; then
        TMP_SUDO=$(mktemp)
        setup_sudo_mode
    fi

    write_unit
    systemctl enable --now portvakt >/dev/null 2>&1 || die "service failed to start; see: journalctl -u portvakt"
    sleep 1
    systemctl is-active --quiet portvakt || die "service is not running; see: journalctl -u portvakt"

    SCHEME="http"
    [ "$SELF_SIGNED" = true ] && SCHEME="https"
    say "Success! portvakt is running on ${SCHEME}://${BIND}"
    [ -n "$PUBLIC_ORIGIN" ] && say "Public URL: ${PUBLIC_ORIGIN}"
    say "Username: ${ADMIN}"
    if [ "$GENERATED" = true ]; then
        say "Password: ${ADMIN_PASSWORD}"
        say "(generated — change it with: sudo portvakt -c ${CONF} user passwd ${ADMIN})"
    fi
    case "$BIND" in
        127.*|localhost*|\[::1\]*)
            say "It only listens locally. From your machine: ssh -L 8443:${BIND} <this-server>, then open ${SCHEME}://localhost:8443" ;;
    esac
    say "Security guide: https://hexagon.github.io/portvakt/docs/security.html"
}

case "$CMD" in
    uninstall) do_uninstall ;;
    update) do_update ;;
    install) do_install ;;
esac
