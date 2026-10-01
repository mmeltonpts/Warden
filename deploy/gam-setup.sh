#!/usr/bin/env bash
#
# Guided GAM7 install and authorisation for Warden.
#
#   sudo ./deploy/gam-setup.sh
#
# Safe to re-run: each step checks whether it is already done and offers to skip it.
# install.sh runs this for you; run it again any time the setup wizard's GAM test fails.
#
# What it sets up, all owned by the `warden` user and stored in its home (/var/lib/warden/.gam):
#   1. GAM7 itself, at /opt/gam7/gam
#   2. A Google Cloud project with the APIs Warden needs, and a service account
#   3. Admin authorisation (oauth2.txt) — directory, reports, Alert Center
#   4. Domain-wide delegation for the service account — Gmail in every mailbox
#
# You need a Google Workspace SUPER ADMIN account and a browser on any computer. The host
# itself needs no browser: GAM prints links, you open them elsewhere and paste back what
# Google gives you.
#
# The service-account key this creates can read and trash mail in every mailbox. It is
# created HERE and never leaves this host. Do not copy one from a workstation: a key issued
# for this host alone can be revoked alone.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/conf.sh"
[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
id -u "$APP_USER" >/dev/null 2>&1 || die "the ${APP_USER} user does not exist — run deploy/install.sh first"
[[ -t 0 ]] || die "this step is interactive — run it from a terminal"

GAM="$GAM_DIR/gam"
CFG="$DATA_DIR/.gam"
gam_as() { sudo -u "$APP_USER" -H "$GAM" "$@"; }

step() { printf '\n\033[1;36m── %s ──\033[0m\n' "$*"; }
pause() { read -r -p "$(printf '\033[1m?\033[0m Press Enter when done (Ctrl-C to stop here)... ')" _ || true; }

# ── 1. install ──────────────────────────────────────────────────────────────
step "1/4  Install GAM7"
if [[ -x "$GAM" ]]; then
  log "GAM7 already installed: $("$GAM" version 2>/dev/null | head -1 || echo "$GAM")"
  if yesno "Update it to the latest release?" n; then
    bash <(curl -s -S -L https://git.io/gam-install) -l -d "$(dirname "$GAM_DIR")"
  fi
else
  log "downloading GAM7 to ${GAM_DIR} (from github.com/GAM-team/GAM)"
  # -l: install only — the project and authorisation steps below run as the warden user,
  # not as root, so the credentials land in warden's home where the app can read them.
  bash <(curl -s -S -L https://git.io/gam-install) -l -d "$(dirname "$GAM_DIR")"
fi
[[ -x "$GAM" ]] || die "GAM7 did not install to ${GAM}"
chown -R "$APP_USER:$APP_USER" "$GAM_DIR"
install -d -o "$APP_USER" -g "$APP_USER" -m 0700 "$CFG"
# Headless host: print links instead of trying to open a browser here.
gam_as config no_browser true save >/dev/null 2>&1 || true

read -r -p "$(printf '\033[1m?\033[0m Super admin email (e.g. admin@your-district.org): ')" ADMIN
[[ "$ADMIN" == *@* ]] || die "need an email address"

# ── 2. project + service account ────────────────────────────────────────────
step "2/4  Google Cloud project and service account"
if [[ -f "$CFG/oauth2service.json" && -f "$CFG/client_secrets.json" ]]; then
  log "already done (oauth2service.json present)"
else
  cat <<EOF
  GAM will now create a Google Cloud project, enable the APIs it needs, and create a
  service account. It prints a link: open it in a browser, sign in as ${ADMIN},
  approve, and paste back what Google shows you. Accept GAM's defaults unless you have
  a reason not to.

EOF
  gam_as create project "$ADMIN"
fi

# ── 3. admin authorisation ──────────────────────────────────────────────────
step "3/4  Admin authorisation"
if gam_as info domain >/dev/null 2>&1; then
  log "already done: $(gam_as info domain 2>/dev/null | grep -i 'Primary Domain' | head -1)"
else
  cat <<EOF
  GAM shows a menu of API scopes. The defaults are right for Warden — in particular
  make sure these are marked [*]:  Alert Center, Directory (users), Reports.
  Type c and Enter to continue, then open the link it prints, sign in as ${ADMIN},
  and paste back the code or the final URL.

EOF
  gam_as oauth create "$ADMIN"
  gam_as info domain >/dev/null || die "admin authorisation did not work — re-run this script"
fi

# ── 4. domain-wide delegation ───────────────────────────────────────────────
step "4/4  Domain-wide delegation (Gmail in every mailbox)"
TEST="$ADMIN"
if gam_as user "$TEST" check serviceaccount >/tmp/warden-gam-check.$$ 2>&1 && ! grep -q '\bFAIL\b' /tmp/warden-gam-check.$$; then
  log "already authorised"
else
  grep -E 'FAIL|PASS' /tmp/warden-gam-check.$$ | head -30 || true
  URL="$(grep -oE 'https://admin\.google\.com/ac/owl/domainwidedelegation[^ ]*' /tmp/warden-gam-check.$$ | head -1 || true)"
  cat <<EOF

  The service account needs these scopes authorised in the Admin console. Open this link
  in a browser signed in as a super admin — it pre-fills the client ID and every scope —
  and click AUTHORISE:

    ${URL:-Admin console → Security → Access and data control → API controls → Manage Domain Wide Delegation}

  Google can take a few minutes to apply it.
EOF
  pause
  for i in 1 2 3 4 5 6; do
    if gam_as user "$TEST" check serviceaccount >/tmp/warden-gam-check.$$ 2>&1 && ! grep -q '\bFAIL\b' /tmp/warden-gam-check.$$; then
      log "domain-wide delegation verified"; break
    fi
    [[ $i -lt 6 ]] && { warn "not active yet — retrying in 30s ($i/5)"; sleep 30; } || {
      grep -E 'FAIL' /tmp/warden-gam-check.$$ | head -10 || true
      warn "still failing. Check the scopes were saved, wait a few minutes, and re-run: sudo $0"
    }
  done
fi
rm -f /tmp/warden-gam-check.$$

# The credential stays readable only by the warden user.
chown -R "$APP_USER:$APP_USER" "$CFG" "$GAM_DIR"
chmod 0700 "$CFG"
chmod 0600 "$CFG"/*.json "$CFG"/oauth2.txt 2>/dev/null || true

step "GAM ready"
cat <<EOF
  GAM path for the setup wizard:  ${GAM}
  Credentials:                    ${CFG}  (warden user only)
  Re-test any time:               sudo -u ${APP_USER} -H ${GAM} user ${TEST} check serviceaccount
EOF
