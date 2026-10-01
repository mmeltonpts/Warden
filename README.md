# Warden

A phishing incident-response console for school districts on Google Workspace.

Warden was built during a real multi-week phishing incident at a K-12 district. It turns the
GAM commands an IT team runs by hand during an incident into a console that a small team can
use under pressure, with the guard rails that incident showed were needed.

- **Reports.** Collects everything staff report to your phish-report mailbox and Gmail's own
  "Report phishing" button (via Google Alert Center). Extracts payload links, unwraps
  redirect wrappers and groups reports by campaign.
- **Scope, sweep, verify.** *Scope* finds a campaign across every mailbox (read-only).
  *Sweep* moves it to Trash and labels it "⚠ PHISHING — DO NOT OPEN". *Verify* then checks
  that nothing survived. Sweeps refuse unsafe queries, such as sender-only searches, and
  never touch your own warnings or responders' copies.
- **Sign-in risk.** Scores each sign-in against that person's own learned normal. It knows
  that a consumer VPN, a passkey, or a sign-in from inside your buildings is not an intrusion.
  It flags sign-ins from outside your home countries.
- **Hunt.** Searches for indicators you learn about later (senders, lure text, payload hosts)
  across mail you already received. This is read-only.
- **Quarantine.** Tracks messages held by your Gmail content-compliance rules. Visible to
  admins only.
- **Optional integrations:**
  - **CrowdStrike Falcon:** endpoint detections, who was signed in when an alert fired, and
    an inventory of remote-access tools.
  - **KnowBe4:** phish-prone context and real-event push-back.
  - **Public threat feeds:** URLhaus, ThreatFox and OpenPhish.
  - **Claude triage:** uses the Claude Code CLI with your Claude subscription. No API key is
    stored.

Everything an operator might want to change is a setting in the console. Secrets are
encrypted in the database. Mail deletion is switched off until someone with root on the host
turns it on.

---

## What you need

| | |
|---|---|
| A dedicated VM | Ubuntu 24.04 LTS, reachable from your **intranet only**, never the internet. Sizes below. |
| Google Workspace | A **super admin** account, used once during setup. |
| A phish-report mailbox | For example `phishing@your-district.org`, the address your Phish Alert Button forwards to. |
| Outbound mail | Google's SMTP relay, set up in the wizard. No password is needed. |
| Optional | KnowBe4 API tokens, a CrowdStrike API client, an abuse.ch key, a Claude subscription. |

### Server size

| | Minimum | Recommended |
|---|---|---|
| vCPU | 2 | 4 |
| RAM | 4 GB | 8 GB |
| Disk | 30 GB | 60 GB |
| OS | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS |

Normal running is light. On a district with about 1,400 staff and 6,300 student mailboxes,
the console, scheduler and GAM together use under 2 GB of RAM. The peaks are:

- **Installs and upgrades.** Building the console (`npm run build`) needs about 2 GB on its
  own. On a 4 GB machine, upgrade outside an incident.
- **Large scans.** A sweep or hunt walks every mailbox in the domain. More CPU makes it no
  faster, because Google's API is the bottleneck. More RAM lets it run while the console
  stays responsive.
- **Disk growth.** The database (sign-in history, reports, alerts) and the job logs grow
  steadily. The recommended 60 GB covers years at that district size. Add more if you keep
  long sign-in history for a very large tenant.

For districts over about 20,000 mailboxes, start at 4 vCPU and 16 GB.

Why a dedicated host: the GAM service-account key that Warden uses can read and trash mail in
**every mailbox in your domain**. The installer creates that key on the host itself, and it
should never live anywhere else.

---

## Install

On the new VM:

```bash
sudo apt-get install -y git
git clone https://github.com/mmeltonpts/Warden.git
cd Warden
sudo ./deploy/install.sh
```

The installer asks a few questions about the **host**. Press Enter to accept the default for
each one.

| Question | Default | Notes |
|---|---|---|
| Console port | `8443` | Any free port except 3006. |
| Networks allowed to reach the console | `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16` | Narrow this to your staff and IT VLANs. Never include your public range. |
| Networks allowed to SSH | Same as above | Only used if you let it configure the firewall. |
| Host name | This host's FQDN | Used for the TLS certificate. |
| HTTPS | Self-signed | Or point it at a certificate from your internal CA. |
| Configure the firewall (ufw)? | Yes | Resets ufw to allow only the networks above. |
| Install the Claude CLI? | No | Only for the optional AI triage. |

It then installs PostgreSQL, Node 22, the console, systemd services, nginx and the firewall.
After that it offers to set up GAM (about 10 minutes):

1. Installs GAM7 to `/opt/gam7`.
2. Creates a Google Cloud project and service account. GAM prints a link: open it on any
   computer, sign in as your super admin, and paste back what Google shows.
3. Authorises admin access (directory, reports, Alert Center).
4. Gives you a link that pre-fills the Admin console with exactly the domain-wide delegation
   scopes to authorise. Click **Authorise**, and the script re-tests until it works.

You can re-run that part on its own at any time with `sudo /opt/warden/deploy/gam-setup.sh`.

At the end, the installer prints the console address and a **one-time setup code**:

```
  Open the console:   https://warden.your-district.org:8443

  ┌──────────────────────────────────────────────┐
  │  One-time setup code:   aB3dE6gH9jK2         │
  └──────────────────────────────────────────────┘
```

### Or: install with Docker

If you would rather run containers, the same console ships as an image,
`ghcr.io/mmeltonpts/warden`. You need Docker with the compose plugin on a Linux host that is
reachable from your intranet only.

```bash
git clone https://github.com/mmeltonpts/Warden.git
cd Warden
./docker/init.sh                 # host name, IP, port, allowed networks, HTTPS; generates secrets
docker compose up -d
docker compose logs warden       # shows the one-time setup code
docker compose run --rm warden gam-setup    # guided GAM authorisation, same steps as above
```

This starts four containers:

| Container | What it does |
|---|---|
| `db` | PostgreSQL. |
| `warden` | The console. |
| `scheduler` | The background jobs. |
| `caddy` | HTTPS and the network allow list. Only its port is published. |

GAM's credentials, the Claude login and job logs live in the `warden-data` volume. They
survive upgrades and never leave that volume.

The setup wizard is the same. Two things differ from a VM install:
- **Enabling sweeps:** set `WARDEN_ALLOW_DESTRUCTIVE=1` in the `.env` next to
  `docker-compose.yml`, then run `docker compose up -d`. That file is on the Docker host,
  where nothing inside the container can write to it.
- **Upgrading:** run `docker compose pull && docker compose up -d`. To stay on one release,
  set `WARDEN_TAG` in `.env` (for example `0.1.0`).

Caddy enforces the allow list using the client's real IP, which Docker preserves on a
normal Linux host. If every request in `docker compose logs caddy` comes from one internal
Docker address, your Docker setup is translating addresses, and the allow list cannot tell
clients apart. In that case, rely on the host firewall instead.

## First-run setup (in the browser)

Open the console address. The first page asks for the setup code and creates your admin
account. The code proves you installed the host, so the first person on the network to load
a new console can't claim it. A **setup wizard** then walks through every setting in order.
Each step includes what to do in Google, KnowBe4 or CrowdStrike, and a test button where one
exists.

1. **General**: the console address and theme.
2. **Google Workspace**: your staff and student domains. *Save & test GAM* checks that GAM
   runs, that admin access works, and that domain-wide delegation covers a real mailbox.
3. **Notifications**: the SMTP relay and who gets alerted. *Save & send a test email*.
4. **Reports**: your phish-report mailbox.
5. **Alerts, Sign-in risk, Quarantine, Hunt**: the defaults are sensible. Add your public
   egress IP so sign-ins from inside your buildings score lower.
6. **Sounds**: an alarm and red banner in every open console when a critical alert arrives.
   Choose the severities, tone and volume, and use *Test sound*. Each browser can mute itself.
7. **Threat feeds, KnowBe4, CrowdStrike, Claude**: optional. Each has its own test, or you
   can skip it.
8. **Schedule**: how often each background job runs.
9. **Finish**: starts the scheduler. **Nothing runs until you press Finish**, so a
   half-configured console never scans with a blank domain.

You can change everything later under **Settings**, or re-run the wizard from Settings.

### Turning on sweeps

Out of the box, Warden **refuses to delete mail**. Scope, verify, hunt and every report
work, but sweeps are refused. Run a few scopes first and read the previews. Then, as root on
the host:

```bash
sudo sed -i 's/WARDEN_ALLOW_DESTRUCTIVE=0/WARDEN_ALLOW_DESTRUCTIVE=1/' \
  /etc/systemd/system/warden-web.service.d/10-destructive.conf
sudo systemctl daemon-reload && sudo systemctl restart warden-web
```

This is deliberately not a button in the console. A setting in the console could be flipped
by anyone who stole a session. This switch needs root on the host.

### Add your team

Under **Users**:
- **ANALYST** is read-only.
- **RESPONDER** can run sweeps.
- **ADMIN** can change settings and is the only role that sees the quarantine.

---

## Releases

Releases are tagged on GitHub (see Releases). Each one publishes a matching Docker image,
`ghcr.io/mmeltonpts/warden:<version>`. On a VM, check out a release with
`git checkout v0.1.0` before running the installer, or follow `main` for the latest.
Versions below 1.0 are marked pre-release.

## Day to day

- **Upgrade:** `cd Warden && git pull && sudo ./deploy/install.sh`. Your answers, secrets,
  data and settings are kept.
- **Change the port, networks or certificate:** re-run the installer; it offers your current
  answers as defaults. For TLS alone:
  - `sudo ./deploy/setup-tls.sh selfsigned [name]`
  - `sudo ./deploy/setup-tls.sh custom fullchain.pem privkey.pem`
- **Logs:** `journalctl -u warden-web -f`. The scheduler is `journalctl -u warden-loginscan`.
- **Lost the setup code** (before the first account exists):
  `sudo -u warden -H bash -c "cd /opt/warden && npx tsx scripts/setup-token.ts"`
- **Every admin locked out:**
  `sudo -u warden -H bash -c "cd /opt/warden && npx tsx scripts/seed-admin.ts you@your-district.org"`
- **Back up:**
  - `/opt/warden/.env`, which holds `WARDEN_MASTER_KEY`. Without it, every saved credential
    has to be re-entered.
  - The database: `sudo -u postgres pg_dump warden > warden.sql`.

## Security model, briefly

- **Network:** intranet only. nginx only accepts the networks you list, and the app itself
  listens on loopback.
- **Configuration:**
  - `.env` holds three bootstrap secrets and nothing else: `DATABASE_URL`, `SESSION_SECRET`
    and `WARDEN_MASTER_KEY`.
  - All other configuration is in the database. Secrets are encrypted with AES-256-GCM.
- **Mail deletion:** gated by a root-owned systemd drop-in, never by a console setting.
- **Sweep guard rails:**
  - Mail is trashed, never deleted, so it can be recovered and kept as evidence.
  - Every sweep is followed by an automatic verify.
  - Sweeps refuse sender-only queries, queries that returned zero results, and anything
    matching your own warnings.
- **GAM:** the service-account key is created on the host and readable only by the `warden`
  user.
- **Claude** (optional): the CLI runs as the `warden` user under a root-owned rules file
  (`deploy/CLAUDE.box.md`). That file limits what it may do on the host.

`CLAUDE.md` records the operational rules this tool enforces and the incident that taught
each one. It's worth reading before changing any sweep or scoring logic.

## Development

```bash
npm ci
npm test          # vitest
npm run typecheck
```

The scripts in `scripts/` run as the `warden` user on the host, for example
`sudo -u warden -H npx tsx scripts/gam-check.ts`. Keep anything specific to your district in
`private/`, which is gitignored. That includes incident records, known-good senders and
partner contacts. **Never commit domains, addresses, IP ranges, hostnames or people's names**;
tests use `example.org` and invented names.

## License

[PolyForm Noncommercial 1.0.0](LICENSE). In plain terms:

- **Schools, districts, government bodies and charities** may use, modify and share Warden
  freely. The license explicitly counts any educational institution or government body as
  permitted use, whatever its funding.
- **Individuals** may use it for any noncommercial purpose, including personal study and
  research.
- **Nobody may sell it**: commercial use is not permitted. That includes selling copies,
  bundling it into a paid product, or charging to host or run it for others.

If you change it and share your version, keep the `LICENSE` file and its `Required Notice`
line. This is source-available software, not "open source" in the OSI sense, because
open-source licenses must allow commercial use.
