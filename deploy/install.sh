#!/usr/bin/env bash
#
# Warden — phishing incident-response console. Installer.
#
#   git clone https://github.com/<you>/Warden.git && cd Warden
#   sudo ./deploy/install.sh
#
# Target:    Ubuntu 24.04 LTS (recommended). Also OK: Ubuntu 26.04, Debian 12/13.
#
# It asks a handful of questions about the HOST (port, which networks may reach it, TLS),
# then installs everything: PostgreSQL, Node, the app, GAM7, systemd units, nginx and the
# firewall. It walks you through authorising GAM, and finishes by printing the console
# address and a one-time setup code. Everything about your DISTRICT — domains, report
# mailboxes, notifications, integrations — is configured afterwards in the browser, by the
# setup wizard that opens on first visit.
#
# Idempotent: re-run it to upgrade or to change an answer. Current answers are offered as
# defaults. For an unattended run, set WARDEN_YES=1 (all defaults) plus any of
# WARDEN_PORT, WARDEN_ALLOW, WARDEN_SERVER_NAME.
#
# Why a dedicated host: GAM's service-account key, created on this host, can read and
# delete mail in EVERY mailbox. It does not belong on a shared box or a workstation.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
. "$HERE/conf.sh"

NODE_MAJOR="22"
DB_NAME="warden"
DB_USER="warden"

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"

# ── distro check ────────────────────────────────────────────────────────────
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
log "detected ${PRETTY_NAME:-unknown}"
case "${ID}:${VERSION_ID}" in
  ubuntu:24.04) ;;
  ubuntu:26.04) warn "Ubuntu 26.04 — newer than the tested target. If NodeSource packaging is not yet published for it, the Node step will fail." ;;
  ubuntu:*|debian:*) warn "untested release — proceeding, but Ubuntu 24.04 LTS is recommended" ;;
  *) die "unsupported distribution '${ID}'. Use Ubuntu 24.04 LTS." ;;
esac

# ── questions ───────────────────────────────────────────────────────────────
load_conf
FIRST_RUN=1; [[ -f "$WARDEN_CONF" ]] && FIRST_RUN=0
PORT="${WARDEN_PORT:-$PORT}"
ALLOW_CIDRS="${WARDEN_ALLOW:-$ALLOW_CIDRS}"
SERVER_NAME="${WARDEN_SERVER_NAME:-$SERVER_NAME}"

cat <<EOF

  Warden installer — a few questions about this host. Press Enter to accept the
  value in [brackets]. Everything about your district is set up later, in the browser.

EOF
ask PORT        "Port the console listens on"
ask ALLOW_CIDRS "Networks allowed to reach the console (space-separated CIDRs; private ranges only)"
ask SSH_CIDRS   "Networks allowed to SSH to this host (used only if you let me configure the firewall)"
ask SERVER_NAME "Name people will use to reach this host (for the certificate)"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "port must be a number"
[[ "$PORT" == "3006" ]] && die "3006 is the app's internal port — pick another"

TLS_CHOICE="selfsigned"
if [[ "$FIRST_RUN" == 1 ]]; then
  echo "  HTTPS: 1) self-signed certificate (default; browsers warn once)"
  echo "         2) my own certificate files (internal CA, wildcard, ...)"
  echo "         3) none — plain HTTP (not recommended)"
  CHOICE="1"; ask CHOICE "Choose 1, 2 or 3"
  case "$CHOICE" in
    2) TLS_CHOICE="custom"
       CERT_IN=""; KEY_IN=""
       ask CERT_IN "Path to the certificate (full-chain PEM)"
       ask KEY_IN  "Path to the private key (PEM)" ;;
    3) TLS_CHOICE="none" ;;
    *) TLS_CHOICE="selfsigned" ;;
  esac
fi
DO_UFW=0;    yesno "Configure the firewall (ufw) to allow only those networks?" y && DO_UFW=1
DO_CLAUDE=0; yesno "Install the Claude Code CLI for optional AI triage? (uses your Claude subscription, no API key)" n && DO_CLAUDE=1
save_conf

# ── packages ────────────────────────────────────────────────────────────────
log "installing base packages"
export DEBIAN_FRONTEND=noninteractive
# Ubuntu's needrestart prompts interactively during apt and hangs an unattended install.
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
apt-get update -qq
apt-get install -y -qq curl ca-certificates gnupg git nginx postgresql \
  postgresql-contrib unzip python3 openssl sudo xz-utils >/dev/null
log "postgresql $(psql --version 2>/dev/null | awk '{print $3}' || echo '?')"

# ── node ────────────────────────────────────────────────────────────────────
if ! command -v node >/dev/null || [[ "$(node -v | cut -c2- | cut -d. -f1)" -lt "$NODE_MAJOR" ]]; then
  log "installing Node ${NODE_MAJOR}.x"
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - >/dev/null
  apt-get install -y -qq nodejs >/dev/null
fi
log "node $(node -v), npm $(npm -v)"

# ── system user ─────────────────────────────────────────────────────────────
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  log "creating system user ${APP_USER}"
  adduser --system --group --home "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi
install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$DATA_DIR" "$DATA_DIR/joblogs"

# ── postgres ────────────────────────────────────────────────────────────────
log "configuring PostgreSQL"
systemctl enable --now postgresql >/dev/null 2>&1 || true
ENV_FILE="$APP_DIR/.env"
if [[ -f "$ENV_FILE" ]] && grep -q '^DATABASE_URL=' "$ENV_FILE"; then
  # Keep the existing password: rotating it on every re-run bought nothing and briefly
  # broke the running service between ALTER ROLE and the restart.
  DB_PASS="$(sed -n 's|^DATABASE_URL="postgresql://[^:]*:\([^@]*\)@.*|\1|p' "$ENV_FILE")"
fi
DB_PASS="${DB_PASS:-$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)}"
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
  sudo -u postgres psql -qc "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASS}';"
else
  sudo -u postgres psql -qc "ALTER ROLE ${DB_USER} PASSWORD '${DB_PASS}';"
fi
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
  || sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"

# ── app ─────────────────────────────────────────────────────────────────────
log "installing application to ${APP_DIR}"
install -d -o "$APP_USER" -g "$APP_USER" -m 0755 "$APP_DIR"
if [[ "$SRC" != "$APP_DIR" ]]; then
  tar -C "$SRC" --exclude node_modules --exclude .next --exclude .git --exclude private -cf - . \
    | tar -C "$APP_DIR" -xf -
fi
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# ── scope of action for the Claude CLI ──────────────────────────────────────
# Warden runs `claude` as this user for triage, and an operator may open an interactive
# session as the same user. Both read user-level memory from the warden user's home, so
# the allowlist goes there.
#
# DO NOT chown or recreate $DATA_DIR/.claude: the CLI keeps its live login there, and taking
# the directory away from the warden user kills triage the next time the session refreshes.
# The FILE is root-owned so the rules cannot be edited in place — a guardrail against drift,
# not a security boundary (the directory owner can still unlink it).
log "installing Claude scope-of-action rules"
[[ -d "$DATA_DIR/.claude" ]] || install -d -o "$APP_USER" -g "$APP_USER" -m 0700 "$DATA_DIR/.claude"
install -o root -g root -m 0644 "$SRC/deploy/CLAUDE.box.md" "$DATA_DIR/.claude/CLAUDE.md"

# ── env: three bootstraps, nothing else ─────────────────────────────────────
# Everything else lives in the database and the Settings UI. WARDEN_ALLOW_DESTRUCTIVE is
# deliberately NOT here: this file is writable by the application user, and a gate on
# district-wide mail deletion that the application can flip is not a gate.
if [[ ! -f "$ENV_FILE" ]]; then
  log "writing ${ENV_FILE}"
  cat >"$ENV_FILE" <<EOF
DATABASE_URL="postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}?schema=public"
SESSION_SECRET="$(openssl rand -hex 32)"
# Unwraps every encrypted settings value (AES-256-GCM). Lose this and every saved
# credential must be re-entered. Back it up somewhere safe.
WARDEN_MASTER_KEY="$(openssl rand -hex 32)"
EOF
else
  log ".env exists — keeping its secrets"
  sed -i "s|^DATABASE_URL=.*|DATABASE_URL=\"postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}?schema=public\"|" "$ENV_FILE"
  grep -q '^WARDEN_MASTER_KEY=' "$ENV_FILE" || printf '\nWARDEN_MASTER_KEY="%s"\n' "$(openssl rand -hex 32)" >>"$ENV_FILE"
  grep -q '^SESSION_SECRET=' "$ENV_FILE"    || printf 'SESSION_SECRET="%s"\n' "$(openssl rand -hex 32)" >>"$ENV_FILE"
  # Settings that used to live here and are now in the console (or derived).
  sed -i '/^WARDEN_ALLOW_DESTRUCTIVE=/d;/^THEME=/d;/^WARDEN_LOG_DIR=/d;/^WARDEN_COOKIE_SECURE=/d' "$ENV_FILE"
fi
chown "$APP_USER:$APP_USER" "$ENV_FILE"
chmod 0600 "$ENV_FILE"

# ── the destructive gate, owned by root ─────────────────────────────────────
# Changing it needs root on this host plus a service restart, so a stolen session cookie
# or an XSS cannot reach it. The single deliberate exception to "configuration lives in
# the console".
DROPIN_DIR="/etc/systemd/system/warden-web.service.d"
DROPIN="$DROPIN_DIR/10-destructive.conf"
if [[ ! -f "$DROPIN" ]]; then
  log "writing ${DROPIN} (sweeps refused until you change it)"
  install -d -m 0755 "$DROPIN_DIR"
  cat >"$DROPIN" <<'EOF'
# Gate on district-wide mail deletion. Sweeps are REFUSED unless this is exactly "1".
#
# Deliberately NOT in .env and NOT in the Settings UI: .env is writable by the application
# user, and a UI toggle is reachable by anything that steals a session. Flipping this
# requires root on this host and a service restart:
#
#   sudo systemctl daemon-reload && sudo systemctl restart warden-web
#
# Leave it at 0 until you have run a SCOPE job on this host and read the preview.
[Service]
Environment=WARDEN_ALLOW_DESTRUCTIVE=0
EOF
  chown root:root "$DROPIN"
  chmod 0644 "$DROPIN"
else
  log "destructive gate already present — left unchanged"
fi

# ── build ───────────────────────────────────────────────────────────────────
# Dev dependencies are REQUIRED for the build (tailwindcss, postcss); prune afterwards.
log "installing npm dependencies (a few minutes)"
as_app "npm ci --no-audit --no-fund"
log "generating Prisma client"
as_app "npx prisma generate"
log "applying database migrations"
as_app "npx prisma migrate deploy"
log "building the console (a few minutes)"
as_app "npm run build"
log "pruning dev dependencies"
as_app "npm prune --omit=dev --no-audit --no-fund" || warn "prune failed — harmless"

# ── systemd ─────────────────────────────────────────────────────────────────
log "installing systemd units"
install -m 0644 "$APP_DIR/deploy/warden-web.service"       /etc/systemd/system/warden-web.service
install -m 0644 "$APP_DIR/deploy/warden-loginscan.service" /etc/systemd/system/warden-loginscan.service
install -m 0644 "$APP_DIR/deploy/warden-loginscan.timer"   /etc/systemd/system/warden-loginscan.timer
systemctl daemon-reload
systemctl enable warden-web >/dev/null
systemctl restart warden-web
# The scheduler tick. It runs nothing until the setup wizard is finished.
systemctl enable --now warden-loginscan.timer >/dev/null

# ── TLS + nginx ─────────────────────────────────────────────────────────────
if [[ "$FIRST_RUN" == 1 ]]; then
  case "$TLS_CHOICE" in
    custom)     bash "$HERE/setup-tls.sh" custom "$CERT_IN" "$KEY_IN" ;;
    none)       bash "$HERE/setup-tls.sh" none ;;
    *)          bash "$HERE/setup-tls.sh" selfsigned ;;
  esac
else
  bash "$HERE/render-nginx.sh"
fi

# ── firewall ────────────────────────────────────────────────────────────────
if [[ "$DO_UFW" == 1 ]]; then
  bash "$HERE/ufw-warden.sh" >/dev/null
  log "firewall: console ${PORT} and SSH 22 open to your networks only"
fi

# ── Claude CLI (optional) ───────────────────────────────────────────────────
if [[ "$DO_CLAUDE" == 1 ]]; then
  if command -v claude >/dev/null; then
    log "Claude Code CLI already installed"
  else
    log "installing the Claude Code CLI"
    npm install -g @anthropic-ai/claude-code --no-audit --no-fund >/dev/null || warn "Claude CLI install failed — triage stays manual"
  fi
fi

# ── GAM ─────────────────────────────────────────────────────────────────────
GAM_OK=0
if [[ -x "$GAM_DIR/gam" ]] && sudo -u "$APP_USER" -H "$GAM_DIR/gam" info domain >/dev/null 2>&1; then
  GAM_OK=1
  log "GAM is installed and authorised"
elif [[ -t 0 && "${WARDEN_YES:-0}" != "1" ]]; then
  cat <<EOF

  GAM is how Warden reads and acts on mail. Setting it up takes about ten minutes and
  needs a Google Workspace super admin account and a browser on any computer.

EOF
  if yesno "Install and authorise GAM now?" y; then
    bash "$HERE/gam-setup.sh" && GAM_OK=1 || warn "GAM setup did not finish — re-run: sudo $APP_DIR/deploy/gam-setup.sh"
  fi
fi

# ── setup code ──────────────────────────────────────────────────────────────
CODE="$(as_app "npx tsx scripts/setup-token.ts" 2>/dev/null | tail -1 || true)"

URL="$(console_url)"
IPURL="$(console_url | sed "s|//${SERVER_NAME}:|//$(hostname -I | awk '{print $1}'):|")"
cat <<EOF

$(log 'Warden installed')

  Open the console:   ${URL}
                      ${IPURL}   (if the name does not resolve yet)
EOF
if [[ "$CODE" =~ ^[A-Za-z0-9_-]{12}$ ]]; then
  cat <<EOF

  ┌──────────────────────────────────────────────┐
  │  One-time setup code:   ${CODE}         │
  └──────────────────────────────────────────────┘

  The first page asks for this code, then creates your admin account and walks you
  through every setting. It expires in 72 hours. New code:
    sudo -u warden -H bash -c "cd ${APP_DIR} && npx tsx scripts/setup-token.ts"
EOF
else
  echo
  echo "  This console already has accounts — sign in as usual."
fi
cat <<EOF

  GAM:                $([[ $GAM_OK == 1 ]] && echo "ready" || echo "NOT authorised yet — sudo ${APP_DIR}/deploy/gam-setup.sh")
  Service:            systemctl status warden-web     (logs: journalctl -u warden-web -f)
  Change host answers: re-run this installer
  Sweeps:             refused until you enable them as root — the setup wizard's last
                      page explains how, and why it is not a button.

EOF
