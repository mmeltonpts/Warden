#!/usr/bin/env bash
#
# Firewall for the Warden host. Intranet only.
#
#   sudo ./deploy/ufw-warden.sh
#
# Uses the port and networks from /etc/warden/install.conf. Warden can trash mail in every
# mailbox in the district and the host holds a domain-wide delegation credential: it should
# be reachable from district networks and nowhere else.
#
# This RESETS ufw. If the host has other firewall rules you need, add them again afterwards.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/conf.sh"
[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
load_conf
command -v ufw >/dev/null || { apt-get install -y -qq ufw >/dev/null; }

log "resetting ufw"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

for NET in $SSH_CIDRS; do
  ufw allow from "$NET" to any port 22 proto tcp comment "ssh" >/dev/null
done
for NET in $ALLOW_CIDRS; do
  ufw allow from "$NET" to any port "$PORT" proto tcp comment "warden console" >/dev/null
done

# Port 3006 is the Next.js process. nginx proxies to it on loopback; it must not be
# reachable directly, or the allow list and TLS are bypassed.
ufw deny 3006/tcp comment "warden app - nginx only" >/dev/null

ufw --force enable >/dev/null
log "ufw active"
ufw status numbered
