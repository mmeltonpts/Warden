#!/usr/bin/env bash
#
# Warden — Proxmox VE helper. Run this ON A PROXMOX HOST (as root) and it creates a dedicated
# Ubuntu 24.04 LXC container and installs Warden inside it, then prints the console URL and the
# one-time setup code.
#
#   bash -c "$(wget -qLO - https://raw.githubusercontent.com/mmeltonpts/Warden/main/deploy/proxmox-install.sh)"
#   # or, from a clone on the PVE host:
#   sudo ./deploy/proxmox-install.sh
#
# It is interactive when run on a terminal (asks a few questions with sensible defaults) and
# fully unattended otherwise — set the WARDEN_* / CT_* variables below to drive it from CI.
#
# Why an LXC and not a VM: Warden is a Node + PostgreSQL + nginx service with no kernel needs,
# so a container is lighter and boots in seconds. It still wants to be a DEDICATED container —
# it holds a GAM service-account key with domain-wide delegation. Keep it on an intranet
# bridge; never give it a public address.

set -euo pipefail

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mXX \033[0m %s\n' "$*" >&2; exit 1; }

command -v pct >/dev/null && command -v pveam >/dev/null || die "this must run on a Proxmox VE host (pct/pveam not found)"
[[ $EUID -eq 0 ]] || die "run as root"

# ── defaults (override with env) ─────────────────────────────────────────────
CTID="${CT_ID:-$(pvesh get /cluster/nextid)}"
HOSTNAME_="${CT_HOSTNAME:-warden}"
CORES="${CT_CORES:-4}"
RAM_MB="${CT_RAM:-8192}"
SWAP_MB="${CT_SWAP:-512}"
DISK_GB="${CT_DISK:-60}"
BRIDGE="${CT_BRIDGE:-vmbr0}"
IPCONF="${CT_IP:-dhcp}"          # dhcp, or e.g. 10.20.1.50/24,gw=10.20.1.1
ROOTFS_STORAGE="${CT_STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${CT_TEMPLATE_STORAGE:-local}"
REPO_URL="${WARDEN_REPO:-https://github.com/mmeltonpts/Warden.git}"
REPO_BRANCH="${WARDEN_BRANCH:-main}"

ask() { local v="$1" p="$2" r; [[ "${WARDEN_YES:-0}" == 1 || ! -t 0 ]] && return 0
  read -r -p "$(printf '\033[1m?\033[0m %s [%s]: ' "$p" "${!v}")" r || true; [[ -n "$r" ]] && printf -v "$v" '%s' "$r"; return 0; }

cat <<EOF

  Warden Proxmox installer. New Ubuntu 24.04 LXC on this host. Enter accepts [default].

EOF
ask CTID            "Container ID"
ask HOSTNAME_       "Hostname"
ask CORES           "CPU cores"
ask RAM_MB          "RAM (MB)"
ask DISK_GB         "Disk (GB)"
ask ROOTFS_STORAGE  "Root filesystem storage"
ask BRIDGE          "Network bridge"
ask IPCONF          "IP (dhcp, or CIDR,gw=...)"

pct status "$CTID" >/dev/null 2>&1 && die "CT $CTID already exists — pick another CT_ID"
pvesm status -storage "$ROOTFS_STORAGE" >/dev/null 2>&1 || die "storage '$ROOTFS_STORAGE' not found (set CT_STORAGE)"

# ── template ─────────────────────────────────────────────────────────────────
log "ensuring an Ubuntu 24.04 LXC template is available"
pveam update >/dev/null 2>&1 || true
TEMPLATE="$(pveam available --section system 2>/dev/null | awk '/ubuntu-24.04-standard/{print $2}' | sort -V | tail -1)"
[[ -n "$TEMPLATE" ]] || die "no ubuntu-24.04-standard template offered by pveam"
if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "$TEMPLATE"; then
  log "downloading $TEMPLATE to $TEMPLATE_STORAGE"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi
TEMPLATE_REF="$TEMPLATE_STORAGE:vztmpl/$TEMPLATE"

# ── create ───────────────────────────────────────────────────────────────────
ROOTPW="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
log "creating LXC $CTID ($HOSTNAME_): ${CORES} cores, ${RAM_MB}MB RAM, ${DISK_GB}GB disk"
# Unprivileged + nesting so systemd (warden-web, the scheduler timer) runs cleanly inside.
pct create "$CTID" "$TEMPLATE_REF" \
  --hostname "$HOSTNAME_" \
  --cores "$CORES" --memory "$RAM_MB" --swap "$SWAP_MB" \
  --rootfs "${ROOTFS_STORAGE}:${DISK_GB}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=${IPCONF}" \
  --unprivileged 1 --features nesting=1 --onboot 1 \
  --ostype ubuntu --password "$ROOTPW" >/dev/null
log "starting container"
pct start "$CTID"

# ── wait for network ─────────────────────────────────────────────────────────
log "waiting for the container network"
for i in $(seq 1 30); do
  pct exec "$CTID" -- bash -c 'getent hosts github.com >/dev/null 2>&1 || ping -c1 -W2 1.1.1.1 >/dev/null 2>&1' && break
  sleep 2
  [[ $i -eq 30 ]] && warn "no outbound network yet — the install step may fail; check the CT's network"
done

# ── install Warden inside the container ──────────────────────────────────────
log "installing Warden inside the container (this takes a few minutes)"
pct exec "$CTID" -- bash -c "
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq git ca-certificates >/dev/null
  rm -rf /opt/warden-src
  git clone --depth 1 --branch '$REPO_BRANCH' '$REPO_URL' /opt/warden-src
  cd /opt/warden-src
  # Non-interactive: defaults for the host answers, no ufw (the LXC sits on your intranet
  # bridge; use the Proxmox firewall), self-signed TLS. Everything else is the setup wizard.
  WARDEN_YES=1 WARDEN_UFW=n bash deploy/install.sh
"

# ── report ───────────────────────────────────────────────────────────────────
CT_IP_ADDR="$(pct exec "$CTID" -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '\r')"
CODE="$(pct exec "$CTID" -- bash -c "cd /opt/warden && sudo -u warden -H npx tsx scripts/setup-token.ts 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r')"

cat <<EOF

$(log "Warden LXC $CTID ready")

  Container:    $CTID ($HOSTNAME_)  —  root password: $ROOTPW
  Console:      https://${CT_IP_ADDR:-<container-ip>}:8443
EOF
if [[ "$CODE" =~ ^[A-Za-z0-9_-]{12}$ ]]; then
  cat <<EOF
  Setup code:   $CODE   (first screen asks for this; expires in 72h)
EOF
fi
cat <<EOF

  Next:
    1. Open the console and complete the setup wizard.
    2. Authorise GAM:   pct exec $CTID -- /opt/warden/deploy/gam-setup.sh
    3. Point an intranet DNS name at the container and (optionally) its own TLS cert.

  Keep this container on an intranet bridge. It must not be reachable from the internet.

EOF
