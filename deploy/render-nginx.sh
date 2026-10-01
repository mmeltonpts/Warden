#!/usr/bin/env bash
#
# Render the nginx site for Warden from /etc/warden/install.conf and reload nginx.
#
#   sudo ./deploy/render-nginx.sh
#
# Called by install.sh, setup-tls.sh and the deploy script. Refuses to install a config
# that fails `nginx -t`, so a bad answer never takes a working console offline.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/conf.sh"
[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
load_conf

TEMPLATE="$HERE/nginx-warden.conf.template"
[[ -f "$TEMPLATE" ]] || die "missing $TEMPLATE"

ALLOW=""
for net in $ALLOW_CIDRS; do ALLOW+="    allow ${net};"$'\n'; done

if [[ "$TLS_MODE" == "none" ]]; then
  SSL=""
  TLS_BLOCK="    # Plain HTTP (TLS_MODE=none). Session cookies cannot be Secure. Run deploy/setup-tls.sh."
else
  [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]] || die "TLS certificate not found ($TLS_CERT / $TLS_KEY) — run deploy/setup-tls.sh"
  SSL="ssl"
  TLS_BLOCK="    ssl_certificate     ${TLS_CERT};
    ssl_certificate_key ${TLS_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security \"max-age=31536000\" always;
    # Someone typing http:// on the HTTPS port gets redirected rather than a 400.
    error_page 497 https://\$http_host\$request_uri;"
fi

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT
# Plain string substitution in Python: sed would interpret the slashes in CIDRs and the
# backslashes and ampersands in the TLS block.
python3 - "$TEMPLATE" "$OUT" "$PORT" "$SSL" "$SERVER_NAME" "$TLS_BLOCK" "$ALLOW" <<'PY'
import sys
src, out, port, ssl, name, tls, allow = sys.argv[1:8]
s = open(src, encoding='utf-8').read()
for k, v in (('__PORT__', port), ('__SSL__', ssl), ('__SERVER_NAME__', name),
             ('__TLS_BLOCK__', tls), ('__ALLOW__', allow.rstrip('\n'))):
    s = s.replace(k, v)
s = s.replace(' ;', ';')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write(s)
PY

SITE=/etc/nginx/sites-available/warden
BACKUP=""
if [[ -f "$SITE" ]]; then BACKUP="$(mktemp)"; cp "$SITE" "$BACKUP"; fi
install -m 0644 "$OUT" "$SITE"
ln -sf "$SITE" /etc/nginx/sites-enabled/warden
rm -f /etc/nginx/sites-enabled/default

if nginx -t >/dev/null 2>&1; then
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
  log "nginx: $(console_url)  (allowed: ${ALLOW_CIDRS})"
else
  nginx -t || true
  if [[ -n "$BACKUP" ]]; then cp "$BACKUP" "$SITE"; warn "new nginx config was invalid — previous config restored"; fi
  die "nginx config invalid; nothing changed"
fi
