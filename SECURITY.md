# Security

Warden is a phishing incident-response console for K-12 Google Workspace districts. It holds
a GAM service account with domain-wide delegation, so its security model is the point, not an
afterthought.

## Reporting a vulnerability
Email the maintainer (see the repo owner) rather than opening a public issue. Please don't
file district data, credentials, or live indicators in an issue or PR.

## Design posture
- **Intranet only.** The console must not be reachable from the internet. nginx/Caddy allow
  only the configured private ranges; the app listens on loopback behind the proxy.
- **Secrets:** three bootstraps in `.env` (`DATABASE_URL`, `SESSION_SECRET`,
  `WARDEN_MASTER_KEY`); everything else is in the database, encrypted at rest with AES-256-GCM
  (`src/lib/crypto.ts`). No credential is ever rendered to the browser in plaintext.
- **Mail deletion** is gated by a root-owned systemd drop-in (`WARDEN_ALLOW_DESTRUCTIVE`), not
  by any console setting — a stolen session cannot enable it.
- **Account response actions** (suspend, reset, deprovision, sign-out) require RESPONDER/ADMIN,
  a typed-mailbox confirmation, and are audited. Nothing is automatic.
- **GAM is invoked with argument arrays, never a shell**, so OS command injection is not
  reachable; sweep/hunt queries are additionally constrained (`assertSweepSafe`, `verifyQuery`).
- **Settings that name an executable are constrained.** `gamPath` is rejected before spawn if
  it is relative or under a temporary/user-writable location, and `ai.command`'s program is
  allow-listed to the Claude CLI (its flags stay configurable). So a stolen or malicious ADMIN
  session cannot turn a setting into host code execution.
- **Login is rate-limited.** Five failed attempts for an account lock it for 15 minutes, and
  failed, locked-out and successful sign-ins are all written to the audit log.
- **Outbound HTTP is allow-listed:** CrowdStrike calls accept only CrowdStrike API hosts;
  RDAP and threat feeds are fixed endpoints.
- **No district data in the repo.** Domains, addresses, IP ranges, hostnames and people's
  names live in the database or the gitignored `private/` directory. Tests use `example.org`
  and invented names.
- **PII retention is configurable.** Sign-in history, reviewed-benign flags, forwarded report
  bodies and student VPN notices can be time-boxed (Settings → Data retention); the prune
  preserves confirmed-incident evidence and never touches the audit log. It is **off by
  default** (0 = keep), so a district sets retention to match its own records policy. Student
  VPN notices are likely a FERPA education record — treat the database accordingly (intranet
  only, encrypted bootstraps, access limited to the `warden` user and your DBAs).

## Dependency / CVE hygiene
- **CI gate:** every push runs `npm audit --omit=dev --audit-level=critical`, so a critical
  advisory in a production dependency fails the build. Dependabot (`.github/dependabot.yml`)
  opens weekly PRs for npm, Docker base images, and GitHub Actions.
- **Release provenance:** each release signs the published image keyless with cosign/Sigstore
  over its digest and attaches an SPDX SBOM to the GitHub Release; it also runs an advisory
  Trivy scan whose HIGH/CRITICAL findings are printed in the release log (base-image CVEs are
  bumped by Dependabot rather than blocking every app release). Verify a pulled image with:
  `cosign verify ghcr.io/<owner>/warden@<digest> --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp 'https://github.com/<owner>/Warden/.*'`
- **Production runtime** dependencies are kept current; `npm prune --omit=dev` removes
  build/test tooling from the deployed host and image, so dev-only advisories (test runner,
  bundler) are not present in the running app. The Prisma CLI is kept as a production
  dependency on purpose — `prisma migrate deploy` runs at container start and on every host
  deploy — but it is a command-line tool invoked at startup, never imported by the web server,
  so its advisories are not reachable from a request.
- Known accepted items: Next.js bundles a `postcss` flagged for build-time source-map/stringify
  issues; Warden processes only first-party CSS at build, so it is not attacker-reachable at
  runtime. It clears when Next ships the patched transitive version.

## Supported versions
The latest tagged release. Older tags do not receive backports.
