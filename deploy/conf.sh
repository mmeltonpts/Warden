# Shared by the deploy scripts. Source it; do not run it.
#
# Host-level answers from install.sh live in /etc/warden/install.conf, root-owned. These are
# the few things that cannot be Settings because they must be decided before the app runs
# or need root to apply: the port nginx listens on, which networks may reach it, the TLS
# certificate. Everything else is in the console.

WARDEN_CONF="/etc/warden/install.conf"

APP_USER="warden"
APP_DIR="/opt/warden"
DATA_DIR="/var/lib/warden"
GAM_DIR="/opt/gam7"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mXX \033[0m %s\n' "$*" >&2; exit 1; }

# Defaults for a first install. Private address space only: this console can trash mail in
# every mailbox in the district and must never be reachable from the internet.
PORT="8443"
ALLOW_CIDRS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
SSH_CIDRS=""
SERVER_NAME=""
TLS_MODE="selfsigned"        # selfsigned | custom | none
TLS_CERT="/etc/ssl/warden/warden.crt"
TLS_KEY="/etc/ssl/warden/warden.key"

load_conf() {
  # shellcheck disable=SC1090
  [[ -f "$WARDEN_CONF" ]] && . "$WARDEN_CONF"
  [[ -n "$SERVER_NAME" ]] || SERVER_NAME="$(hostname -f 2>/dev/null || hostname)"
  [[ -n "$SSH_CIDRS" ]] || SSH_CIDRS="$ALLOW_CIDRS"
  return 0
}

save_conf() {
  install -d -m 0755 "$(dirname "$WARDEN_CONF")"
  cat >"$WARDEN_CONF" <<EOF
# Written by deploy/install.sh. Re-run the installer to change these; it offers the
# current values as defaults. Root-owned on purpose.
PORT="${PORT}"
ALLOW_CIDRS="${ALLOW_CIDRS}"
SSH_CIDRS="${SSH_CIDRS}"
SERVER_NAME="${SERVER_NAME}"
TLS_MODE="${TLS_MODE}"
TLS_CERT="${TLS_CERT}"
TLS_KEY="${TLS_KEY}"
EOF
  chown root:root "$WARDEN_CONF"
  chmod 0644 "$WARDEN_CONF"
}

# ask VAR "Question" — shows the current value as the default. Non-interactive runs
# (no terminal, or WARDEN_YES=1) keep the default silently.
ask() {
  local var="$1" prompt="$2" cur reply
  cur="${!var}"
  if [[ "${WARDEN_YES:-0}" == "1" || ! -t 0 ]]; then return 0; fi
  read -r -p "$(printf '\033[1m?\033[0m %s [%s]: ' "$prompt" "$cur")" reply || true
  [[ -n "$reply" ]] && printf -v "$var" '%s' "$reply"
  return 0
}

# yesno "Question" y|n — returns 0 for yes.
yesno() {
  local prompt="$1" def="${2:-y}" reply
  if [[ "${WARDEN_YES:-0}" == "1" || ! -t 0 ]]; then [[ "$def" == "y" ]]; return; fi
  read -r -p "$(printf '\033[1m?\033[0m %s [%s]: ' "$prompt" "$([[ $def == y ]] && echo Y/n || echo y/N)")" reply || true
  reply="${reply:-$def}"
  [[ "${reply,,}" == y* ]]
}

as_app() { sudo -u "$APP_USER" -H bash -lc "cd '$APP_DIR' && $*"; }

console_url() {
  local scheme="https"
  [[ "$TLS_MODE" == "none" ]] && scheme="http"
  printf '%s://%s:%s' "$scheme" "$SERVER_NAME" "$PORT"
}
