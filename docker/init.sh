#!/usr/bin/env bash
#
# Create the .env file for `docker compose`. Asks about the host, generates the secrets.
#
#   ./docker/init.sh
#
# Re-running keeps the existing secrets and offers the current answers as defaults. The
# database password and WARDEN_MASTER_KEY must never change once data exists: the master
# key unwraps every credential saved in the console.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ENV=.env
[[ -f "$ENV" ]] && set -a && . "./$ENV" && set +a

rand() { openssl rand -hex 32; }
ask() {
  local var="$1" prompt="$2" cur reply
  cur="${!var:-}"
  read -r -p "$(printf '\033[1m?\033[0m %s [%s]: ' "$prompt" "$cur")" reply || true
  [[ -n "$reply" ]] && printf -v "$var" '%s' "$reply"
  return 0
}
command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }

HOST_NAME="${HOST_NAME:-$(hostname -f 2>/dev/null || hostname)}"
HOST_IP="${HOST_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
WARDEN_PORT="${WARDEN_PORT:-8443}"
WARDEN_ALLOW_CIDRS="${WARDEN_ALLOW_CIDRS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
TLS_MODE="${TLS_MODE:-internal}"

echo
echo "  Warden (Docker) — questions about this host. Enter accepts the [default]."
echo
ask HOST_NAME          "Name people will use to reach the console"
ask HOST_IP            "This host's IP address (also accepted)"
ask WARDEN_PORT        "Port"
ask WARDEN_ALLOW_CIDRS "Networks allowed to reach the console (space-separated, private ranges only)"
ask TLS_MODE           "HTTPS: 'internal' (self-signed) or 'custom' (put fullchain.pem + privkey.pem in ./certs)"

SCHEME=https
case "$TLS_MODE" in
  custom) WARDEN_TLS="/certs/fullchain.pem /certs/privkey.pem"
          [[ -f certs/fullchain.pem && -f certs/privkey.pem ]] || echo "  !! put certs/fullchain.pem and certs/privkey.pem in place before starting" ;;
  *)      TLS_MODE=internal; WARDEN_TLS=internal ;;
esac
mkdir -p certs
WARDEN_SITES="${SCHEME}://${HOST_NAME}:${WARDEN_PORT}"
[[ -n "$HOST_IP" ]] && WARDEN_SITES="${WARDEN_SITES}, ${SCHEME}://${HOST_IP}:${WARDEN_PORT}"

umask 077
cat >"$ENV" <<EOF
# Warden — Docker settings. Written by docker/init.sh; re-run it to change answers.
# Everything about your district is configured in the console's setup wizard, not here.

HOST_NAME="${HOST_NAME}"
HOST_IP="${HOST_IP}"
WARDEN_PORT="${WARDEN_PORT}"
WARDEN_ALLOW_CIDRS="${WARDEN_ALLOW_CIDRS}"
TLS_MODE="${TLS_MODE}"
WARDEN_SITES="${WARDEN_SITES}"
WARDEN_TLS="${WARDEN_TLS}"

# Image version. "latest", or pin a release such as 0.1.0.
WARDEN_TAG="${WARDEN_TAG:-latest}"

# Secrets — generated once. Back this file up: without WARDEN_MASTER_KEY every credential
# saved in the console must be re-entered. Never change POSTGRES_PASSWORD after first start.
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(rand)}"
SESSION_SECRET="${SESSION_SECRET:-$(rand)}"
WARDEN_MASTER_KEY="${WARDEN_MASTER_KEY:-$(rand)}"

# Gate on district-wide mail deletion. Leave 0 until you have run a scope and read the
# preview; set 1 and run "docker compose up -d" to enable sweeps.
WARDEN_ALLOW_DESTRUCTIVE="${WARDEN_ALLOW_DESTRUCTIVE:-0}"
EOF

cat <<EOF

  Wrote .env (readable by you only). Next:

    docker compose up -d
    docker compose logs warden          # shows the one-time setup code
    open ${WARDEN_SITES%%,*}

  Then, for GAM:  docker compose run --rm warden gam-setup

EOF
