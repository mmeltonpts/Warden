#!/usr/bin/env bash
#
# Provision the agent account on the Warden host.
#
# Creates `warden-agent`, installs the workstation's public key, and grants a
# NARROW sudo scope — enough to operate and debug Warden, not enough to be root.
#
#   sudo ./deploy/agent-access.sh 'ssh-ed25519 AAAA... warden-agent@...'
#
# The key may only be used from the networks in SSH_CIDRS in /etc/warden/install.conf
# (set by install.sh), or from WARDEN_AGENT_FROM if you set it, e.g.
#   sudo WARDEN_AGENT_FROM="10.20.0.0/16" ./deploy/agent-access.sh '<key>'
#
# ── What this account is, in plain terms ────────────────────────────────────
# The matching private key lives on an operator's workstation, e.g.
#   ~/.ssh/warden_agent_ed25519
# and is used by Claude Code sessions running on that workstation. It is NOT tied
# to a person and NOT tied to a single session — anyone with access to that
# laptop can use it, and no session remembers what a previous one did with it.
#
# So it is scoped as a service account, not an administrator:
#   * no shell password, key-only
#   * sudo limited to the Warden unit, its logs, and its own scripts
#   * explicitly DENIED the GAM credential, user management, and shell escapes
#
# If you need full root on this box, log in as yourself. That keeps
# `journalctl _UID=` and the WardenAudit table honest about who did what.

set -euo pipefail

AGENT_USER="warden-agent"
APP_USER="warden"
APP_DIR="/opt/warden"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mXX \033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0 '<public key>')"
PUBKEY="${1:-}"
[[ -n "$PUBKEY" ]] || die "usage: $0 '<ssh-ed25519 AAAA... comment>'"
[[ "$PUBKEY" == ssh-ed25519\ * ]] || die "expected an ed25519 public key"

# ── account ─────────────────────────────────────────────────────────────────
if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
  log "creating ${AGENT_USER}"
  adduser --disabled-password --gecos "Warden agent (Claude Code)" \
          "$AGENT_USER"
fi
# No password login, ever. Key only.
passwd -l "$AGENT_USER" >/dev/null

install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "/home/$AGENT_USER/.ssh"
AUTH="/home/$AGENT_USER/.ssh/authorized_keys"

# Source restriction: the key only works from your own networks.
FROM="${WARDEN_AGENT_FROM:-}"
if [[ -z "$FROM" && -f /etc/warden/install.conf ]]; then
  FROM="$(. /etc/warden/install.conf; echo "${SSH_CIDRS:-$ALLOW_CIDRS}")"
fi
FROM="${FROM:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
OPTS="from=\"$(echo "$FROM" | tr ' ' ',')\",no-agent-forwarding,no-X11-forwarding,no-user-rc"

if grep -qF "$PUBKEY" "$AUTH" 2>/dev/null; then
  log "key already authorised"
else
  log "installing key"
  printf '%s %s\n' "$OPTS" "$PUBKEY" >>"$AUTH"
fi
chown "$AGENT_USER:$AGENT_USER" "$AUTH"
chmod 0600 "$AUTH"

# ── sudo scope ──────────────────────────────────────────────────────────────
# Deliberately narrow. Each entry exists because operating Warden needs it.
log "writing sudoers scope"
cat >/etc/sudoers.d/warden-agent <<EOF
# Warden agent — narrow operational scope. NOT an administrator.
# Regenerate with deploy/agent-access.sh; do not hand-edit.

Cmnd_Alias WARDEN_SVC   = /usr/bin/systemctl status warden-web, \\
                          /usr/bin/systemctl restart warden-web, \\
                          /usr/bin/systemctl stop warden-web, \\
                          /usr/bin/systemctl start warden-web, \\
                          /usr/bin/systemctl status warden-loginscan.timer, \\
                          /usr/bin/systemctl start warden-loginscan.service, \\
                          /usr/bin/systemctl list-timers warden-*

Cmnd_Alias WARDEN_LOGS  = /usr/bin/journalctl -u warden-web *, \\
                          /usr/bin/journalctl -u warden-loginscan *

${AGENT_USER} ALL=(root) NOPASSWD: WARDEN_SVC, WARDEN_LOGS
# App scripts (scans, migrations, seeding) run AS the warden user, never as root.
${AGENT_USER} ALL=(${APP_USER}) NOPASSWD: /usr/bin/npx, /usr/bin/npm

# ── explicitly denied ──────────────────────────────────────────────────────
# The GAM service-account key is the crown jewel: domain-wide delegation over
# every mailbox in the district. An unattended key must not be able to read it,
# copy it, or hand itself a shell that could.
${AGENT_USER} ALL=(ALL) !/bin/su, !/usr/bin/su, !/bin/bash, !/bin/sh, !/usr/bin/sudo -i, \\
    !/usr/bin/passwd, !/usr/sbin/adduser, !/usr/sbin/useradd, !/usr/sbin/usermod, \\
    !/usr/sbin/visudo, !/bin/cat /opt/gam7/oauth2service.json, \\
    !/bin/cp /opt/gam7/*, !/usr/bin/tar *gam7*
EOF
chmod 0440 /etc/sudoers.d/warden-agent
visudo -cf /etc/sudoers.d/warden-agent >/dev/null || {
  rm -f /etc/sudoers.d/warden-agent
  die "sudoers validation failed — nothing installed"
}

# ── read access to job logs, not to credentials ─────────────────────────────
if getent group "$APP_USER" >/dev/null 2>&1; then
  usermod -aG "$APP_USER" "$AGENT_USER"
  log "added ${AGENT_USER} to the ${APP_USER} group (job-log read access)"
else
  warn "group '${APP_USER}' does not exist yet — run deploy/install.sh first, then"
  warn "re-run this script to grant job-log read access. Service control works now."
fi
chmod 0750 /var/lib/warden 2>/dev/null || true
# GAM's credential stays readable only by the warden user.
chmod 0700 /opt/gam7 2>/dev/null || true
chmod 0600 /opt/gam7/oauth2service.json 2>/dev/null || true

cat <<EOF

$(log "${AGENT_USER} provisioned")

  Test from the workstation:
    ssh -i ~/.ssh/warden_agent_ed25519 ${AGENT_USER}@$(hostname -I | awk '{print $1}') \\
        sudo systemctl status warden-web

  Scope granted:   warden-web + loginscan control, their journals,
                   npm/npx as the ${APP_USER} user
  Scope denied:    root shell, su, user management, the GAM credential

  Revoke instantly:
    sudo rm /etc/sudoers.d/warden-agent
    sudo userdel -r ${AGENT_USER}

  This key is not tied to a person. If it is ever used for something nobody can
  account for, revoke first and ask questions after — that is cheap here.

EOF
