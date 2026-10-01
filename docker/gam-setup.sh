#!/usr/bin/env bash
#
# Guided GAM authorisation inside the container. Run interactively:
#
#   docker compose run --rm warden gam-setup
#
# Same steps as deploy/gam-setup.sh on a host install. GAM is already in the image; this
# creates the Google Cloud project, admin authorisation and domain-wide delegation, and
# stores them in the warden user's home — the `warden-data` volume — so they survive
# container upgrades. The service-account key never leaves that volume.

set -euo pipefail
GAM=/opt/gam7/gam
CFG=/var/lib/warden/.gam
[[ -t 0 ]] || { echo "interactive — run: docker compose run --rm warden gam-setup"; exit 1; }
if [[ "$(id -u)" == "0" ]]; then
  gam_as() { setpriv --reuid=warden --regid=warden --init-groups -- "$GAM" "$@"; }
else
  gam_as() { "$GAM" "$@"; }
fi
step() { printf '\n\033[1;36m── %s ──\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }

gam_as config no_browser true save >/dev/null 2>&1 || true
read -r -p "Super admin email (e.g. admin@your-district.org): " ADMIN
[[ "$ADMIN" == *@* ]] || { echo "need an email address"; exit 1; }

step "1/3  Google Cloud project and service account"
if [[ -f "$CFG/oauth2service.json" ]]; then ok "already done"; else
  echo "  GAM prints a link: open it in a browser, sign in as ${ADMIN}, approve, and paste back what Google shows."
  gam_as create project "$ADMIN"
fi

step "2/3  Admin authorisation"
if gam_as info domain >/dev/null 2>&1; then ok "already done"; else
  echo "  Accept the default scopes (make sure Alert Center, Directory and Reports are [*]), type c, then follow the link."
  gam_as oauth create "$ADMIN"
fi

step "3/3  Domain-wide delegation"
for i in 1 2 3 4 5 6 7; do
  OUT="$(gam_as user "$ADMIN" check serviceaccount 2>&1 || true)"
  if ! grep -q '\bFAIL\b' <<<"$OUT" && grep -q 'PASS' <<<"$OUT"; then ok "verified"; break; fi
  URL="$(grep -oE 'https://admin\.google\.com/ac/owl/domainwidedelegation[^ ]*' <<<"$OUT" | head -1 || true)"
  if [[ $i == 1 ]]; then
    echo "  Open this link signed in as a super admin and click AUTHORISE (it pre-fills every scope):"
    echo "    ${URL:-Admin console → Security → API controls → Manage Domain Wide Delegation}"
    read -r -p "  Press Enter when done... " _ || true
  elif [[ $i == 7 ]]; then
    echo "  Still not active. Google can take several minutes — run this again later."; exit 1
  else
    echo "  not active yet — retrying in 30s"; sleep 30
  fi
done

step "GAM ready"
echo "  In the setup wizard, the GAM path is: ${GAM}"
