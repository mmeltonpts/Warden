#!/usr/bin/env bash
#
# Container entrypoint. Starts as root only long enough to fix volume ownership and put the
# Claude rules file in place (root-owned, as on a host install), then drops to `warden` for
# everything that touches mail.
#
#   web          the console (default)
#   scheduler    the background jobs — runs scripts/tick.ts every two minutes
#   gam-setup    guided GAM authorisation (interactive: docker compose run --rm warden gam-setup)
#   setup-token  print a new one-time setup code
#   seed-admin   recovery: create an admin  (seed-admin you@your-district.org)
#   claude       the Claude CLI as the warden user (to /login for AI triage)
#   shell        a shell as the warden user

set -euo pipefail
APP=/app
HOME_DIR=/var/lib/warden
log() { printf '[warden] %s\n' "$*"; }

for v in DATABASE_URL SESSION_SECRET WARDEN_MASTER_KEY; do
  [[ -n "${!v:-}" ]] || { log "missing ${v} — run docker/init.sh to create the .env file"; exit 1; }
done

if [[ "$(id -u)" == "0" ]]; then
  AS=(setpriv --reuid=warden --regid=warden --init-groups --inh-caps=-all --)
  install -d -o warden -g warden -m 0750 "$HOME_DIR" "$HOME_DIR/joblogs"
  install -d -o warden -g warden -m 0700 "$HOME_DIR/.gam" "$HOME_DIR/.claude"
  # Root-owned so the app cannot edit its own rules in place. The directory is warden's, so
  # this is a guardrail against drift, not a boundary — the same as on a host install.
  install -o root -g root -m 0644 "$APP/deploy/CLAUDE.box.md" "$HOME_DIR/.claude/CLAUDE.md"
else
  AS=()
fi

cd "$APP"
cmd="${1:-web}"; shift || true

case "$cmd" in
  web)
    log "applying database migrations"
    "${AS[@]}" npx prisma migrate deploy
    # Issues a code only while the console has no accounts; otherwise prints a notice.
    OUT="$("${AS[@]}" npx tsx scripts/setup-token.ts 2>/dev/null | tail -1 || true)"
    if [[ "$OUT" =~ ^[A-Za-z0-9_-]{12}$ ]]; then
      cat <<EOF

  ┌───────────────────────────────────────────────────────────┐
  │  Warden is waiting to be set up.                          │
  │  Open the console and enter this one-time setup code:     │
  │                                                           │
  │      ${OUT}                                         │
  │                                                           │
  │  It expires in 72 hours. A new code is issued on restart, │
  │  or: docker compose exec warden setup-token               │
  └───────────────────────────────────────────────────────────┘

EOF
    fi
    log "starting the console on :3006"
    exec "${AS[@]}" npx next start -p 3006 -H 0.0.0.0
    ;;
  scheduler)
    log "scheduler: running due jobs every 2 minutes (nothing runs until setup is finished)"
    while true; do
      "${AS[@]}" npx tsx scripts/tick.ts || log "tick failed — will retry"
      sleep 120
    done
    ;;
  gam-setup)   exec bash "$APP/docker/gam-setup.sh" ;;
  setup-token) exec "${AS[@]}" npx tsx scripts/setup-token.ts ;;
  seed-admin)  exec "${AS[@]}" npx tsx scripts/seed-admin.ts "$@" ;;
  claude)      exec "${AS[@]}" claude "$@" ;;
  shell)       exec "${AS[@]}" bash "$@" ;;
  *)           exec "$cmd" "$@" ;;
esac
