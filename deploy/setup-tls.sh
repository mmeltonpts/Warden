#!/usr/bin/env bash
#
# Warden TLS.
#
#   sudo ./deploy/setup-tls.sh                       self-signed for the configured name
#   sudo ./deploy/setup-tls.sh selfsigned [name]     same, optionally for a different name
#   sudo ./deploy/setup-tls.sh custom CERT KEY       use your own certificate (e.g. from
#                                                    your internal CA) — full-chain PEM + key
#   sudo ./deploy/setup-tls.sh none                  plain HTTP (not recommended)
#
# The console is intranet-only, so Let's Encrypt usually cannot validate it. A self-signed
# certificate makes browsers warn once; a certificate from your internal CA does not.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/conf.sh"
[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
load_conf

MODE="${1:-selfsigned}"
case "$MODE" in
  selfsigned)
    [[ -n "${2:-}" ]] && SERVER_NAME="$2"
    TLS_CERT="/etc/ssl/warden/warden.crt"
    TLS_KEY="/etc/ssl/warden/warden.key"
    install -d -m 0755 /etc/ssl/warden
    IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    SAN="DNS:${SERVER_NAME}"
    [[ -n "$IP" ]] && SAN="${SAN},IP:${IP}"
    log "issuing a self-signed certificate for ${SERVER_NAME}${IP:+ and ${IP}} (10 years)"
    openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
      -keyout "$TLS_KEY" -out "$TLS_CERT" \
      -subj "/CN=${SERVER_NAME}" -addext "subjectAltName=${SAN}" 2>/dev/null
    chmod 0600 "$TLS_KEY"
    TLS_MODE="selfsigned"
    ;;
  custom)
    [[ -f "${2:-}" && -f "${3:-}" ]] || die "usage: $0 custom /path/fullchain.pem /path/privkey.pem"
    install -d -m 0755 /etc/ssl/warden
    install -m 0644 "$2" /etc/ssl/warden/custom.crt
    install -m 0600 "$3" /etc/ssl/warden/custom.key
    TLS_CERT="/etc/ssl/warden/custom.crt"
    TLS_KEY="/etc/ssl/warden/custom.key"
    TLS_MODE="custom"
    log "using your certificate"
    ;;
  none)
    warn "serving plain HTTP: passwords and session cookies cross the network unencrypted"
    TLS_MODE="none"
    ;;
  *) die "unknown mode '$MODE' (selfsigned | custom | none)" ;;
esac

save_conf
bash "$HERE/render-nginx.sh"
log "console: $(console_url)"
[[ "$TLS_MODE" == "selfsigned" ]] && log "browsers will warn once about the self-signed certificate — expected on an internal host"
exit 0
