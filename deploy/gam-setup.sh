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

# GAM7, pinned and fetched straight from the GAM-team GitHub release — the same method the
# Docker image uses (see Dockerfile). The old `curl … git.io/gam-install | bash` is gone: git.io
# was sunset by GitHub in 2022, so it was both broken and an unpinned remote-code path for the
# one binary that holds domain-wide delegation. Bump GAM_VERSION to upgrade (releases:
# github.com/GAM-team/GAM/releases). Set GAM_SHA256_x86_64 / GAM_SHA256_arm64 to verify the
# tarball against a known hash; left unset, it relies on HTTPS + GitHub integrity and says so.
GAM_VERSION="${GAM_VERSION:-7.48.14}"
gam_download() {
  local arch
  case "$(uname -m)" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m) — install GAM manually from github.com/GAM-team/GAM/releases and set its path in the wizard" ;;
  esac
  local url="https://github.com/GAM-team/GAM/releases/download/v${GAM_VERSION}/gam-${GAM_VERSION}-linux-${arch}-glibc2.35.tar.xz"
  local tmp; tmp="$(mktemp -d)"
  log "downloading GAM ${GAM_VERSION} (${arch}) from the GAM-team GitHub release"
  curl -fsSL -o "$tmp/gam.tar.xz" "$url" || { rm -rf "$tmp"; die "GAM download failed: $url"; }
  local var="GAM_SHA256_${arch}"; local want="${!var:-}"
  if [[ -n "$want" ]]; then
    echo "${want}  ${tmp}/gam.tar.xz" | sha256sum -c - >/dev/null 2>&1 \
      || { rm -rf "$tmp"; die "GAM tarball checksum mismatch — refusing to install"; }
    log "checksum verified"
  else
    warn "no pinned checksum for ${arch}; proceeding on HTTPS + GitHub release integrity"
  fi
  # The tarball contains a top-level gam7/ directory, so extracting into $(dirname "$GAM_DIR")
  # (normally /opt) lands the binary at $GAM_DIR/gam.
  tar -xJf "$tmp/gam.tar.xz" -C "$(dirname "$GAM_DIR")" || { rm -rf "$tmp"; die "GAM extract failed"; }
  rm -rf "$tmp"
}

# ── 1. install ──────────────────────────────────────────────────────────────
step "1/4  Install GAM7"
if [[ -x "$GAM" ]]; then
  log "GAM7 already installed: $("$GAM" version 2>/dev/null | head -1 || echo "$GAM")"
  if yesno "Re-install / update to GAM ${GAM_VERSION}?" n; then
    gam_download
  fi
else
  log "installing GAM ${GAM_VERSION} to ${GAM_DIR}"
  # Binary only: the project and authorisation steps below run as the warden user, not root,
  # so the credentials land in warden's home where the app can read them.
  gam_download
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
  # GAM 7.x prints its own shortener (gam-shortn.appspot.com) that redirects to the DWD page;
  # older GAM printed the admin.google.com URL directly. Match either, newest form first.
  URL="$(grep -oE 'https://(gam-shortn\.appspot\.com/[^ ]+|admin\.google\.com/ac/owl/domainwidedelegation[^ ]*)' /tmp/warden-gam-check.$$ | head -1 || true)"
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
