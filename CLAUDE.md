# Warden — read this first

Phishing incident response for a K-12 district: ~1,360 staff mailboxes, ~6,300 student
mailboxes, one GAM service account with domain-wide delegation. A mistake here deletes a
partner district's IEP casework, or quarantines a student self-harm alert.

## Configuration rules (apply to every project, not just this one)

**Every configurable thing lives in the database and the Settings UI.** Not `.env`, not a
constant, not a flag someone has to SSH in to change. If an operator could plausibly want
it different, it is a setting with a form field.

**Secrets in the database are encrypted at rest.** AES-256-GCM via `src/lib/crypto.ts`.
Encrypted values are stored as `enc:v1:<iv>:<tag>:<ciphertext>` so an unencrypted legacy
value is obvious on sight and can be migrated in place. Never store a credential, API key,
or service-account path as plaintext in a settings row.

**`.env` carries bootstraps only** — the three secrets that must exist before the database
can be read at all:

    DATABASE_URL          where the settings live
    SESSION_SECRET        session signing
    WARDEN_MASTER_KEY     unwraps the encrypted settings

Anything else in `.env` is a bug. (Cookie `Secure` follows the protocol nginx reports, and
the theme is a setting — neither belongs here.)

**Docker is the same rule in a different place.** The compose `.env` beside
`docker-compose.yml` lives on the Docker host and carries the bootstraps, the host answers
(port, sites, allow list) and `WARDEN_ALLOW_DESTRUCTIVE` — the container cannot write it,
which is what makes it an acceptable home for the gate. Host-side commands shown in the
console come from `src/lib/runtime.ts`, never hard-coded.

### The one deliberate exception

**`WARDEN_ALLOW_DESTRUCTIVE` is NOT a UI setting and must never become one.**

It lives in a root-owned systemd drop-in at
`/etc/systemd/system/warden-web.service.d/10-destructive.conf`. It is the gate on
district-wide mail deletion. A setting in the UI can be flipped by anyone who steals a
session cookie or finds an XSS; this one requires root on the host and a service restart.

It previously lived in `.env` — which the deploy agent can write, since it executes code as
the `warden` user. That made the gate decorative. If you find yourself moving it back for
convenience, you are removing the only thing standing between a stolen session and 7,697
mailboxes.

## Operational rules, each paid for in September 2026

**Gmail search cannot reliably match a bare domain inside a URL.** A scan for
`downloaddocc.com` returned ZERO hits for a domain provably present in message bodies.
Scope on LURE TEXT; confirm payloads by fetching bodies. Content-compliance rules are
different — they substring-match the body and *will* match the URL.

**Never sweep on `from:` alone.** A sender-scoped sweep of a compromised partner-district account would
have destroyed 51 live IEP and case-conference messages. `assertSweepSafe()` refuses it.

**Never HUNT on `from:` alone either.** The same fact bites without deleting anything. An
unscoped sender indicator returned 1,981 findings in one 45-day dry run — mostly a partner
district's athletic director sending "Cross Country" and "Weather Protocol", because that
account was compromised for a few days and is a real colleague the rest of the time. Every
sender term carries a date window around `firstSeen` (`hunt.senderWindowDays`, defaulting
to 5); `huntTerms()` has no branch that emits a bare `from:`. A hunt nobody reads fails the
same way a hunt that finds nothing does.

**Never attribute a hit to an indicator you cannot show matched.** Gmail matches lure
strings against the BODY, which `print messages` does not return, so subject-matching is
the only attribution available and it often finds nothing. The first version fell back to
"the first lure string in the list" and labelled every unrelated message with an indicator
from a different campaign. Unattributed is a fact; a wrong attribution sends an analyst
after the wrong attack.

**Always verify after acting.** A bulk sweep reported success while one copy survived
unlabelled outside the Inbox in one mailbox. Every SWEEP auto-queues its VERIFY.

**An empty result and a failed result are not the same thing.** This is the most repeated
bug in this codebase, and it always reads as good news. `readIfExists` returns `''` on any
error and the CSV parser returns `[]` for anything under two lines, so a GAM killed at the
scan timeout produces exactly the same zero rows as a genuinely clean domain. `doVerify`
said `clean = rows.length === 0` and printed **"Verified clean"** in green while writing
`verified: true` to the audit log — the founding incident rebuilt inside the check that
exists to catch it. Same shape in `doAccountCheck` ("clean — no persistence indicators"
over a GAM that never ran) and in `runOne`, which set `status: 'DONE'` unconditionally
while `exitCode` was stored and read by nothing — `grep -rn "exitCode|timedOut" src/app`
returned zero hits.

Every job now carries `exitCode` and `timedOut`, `DONE` requires both to be good, and
anything else is `INCOMPLETE`, which closes the sweep gate and never renders green.
**Silence must mean "checked and clear", never "could not check"** — an inconclusive verify
emails, exactly as survivors do.

**A verify must measure the set the sweep actually touched.** `runVerify` omitted
`protectiveSuffix`, so every responder copy the sweep deliberately spared came back as a
"survivor" and alerted every time staff used the Phish Alert Button — a verify that cries
wolf by construction is as useless as one that always says clean. It also inherited the
operator's scope query, which may lack `in:anywhere`, and the surviving copy in the
founding incident was unlabelled and *outside the Inbox*: exactly where a default-scope
query cannot look. `verifyQuery()` forces both, with tests.

**A zero-result scope is a reason to re-read the query, never a reason to sweep.** The gate
requires at least one finding, because a scan for a domain provably present in message
bodies returned zero.

**Extract every link and decode redirect wrappers.** A payload behind
`google.com/url?q=` was invisible to a filter that excluded "google", and a `head -2`
truncated another. Both let real phish through a verification that reported clean.

**Never sweep responders.** `[Phish Alert]`, `DO NOT OPEN`, `Phishing Alert`, `Heads Up`
and internal senders are excluded from every sweep. Those messages are the record of who
caught the attack.

**Trash, never delete.** Recoverable, and it stays available as evidence.

**Measure a content rule against live mail before enabling it.** A superintendent-
impersonation rule quarantined 164 legitimate replies in one day, and a later version
caught student-safety alerts because two unrelated staff shared the impersonated
superintendent's first and last names between them. Name matching on independent tokens
does not work in a district with 16 Amandas.

**SPF/DKIM/DMARC passing means nothing.** Every confirmed attack came from a genuinely
compromised, fully authenticated partner-district account.

## Detection rules

**Score against the baseline as it was BEFORE the scan window.** Otherwise an intrusion
teaches the baseline that the intruder is normal.

**A network seen once is not normal.** `buildBaseline` requires two sightings. Once is what
a first intrusion looks like.

**A consumer VPN is one fact, not three.** A privacy relay presents a new network, a new
ASN and a new region simultaneously, because that is the product. Scoring all three as
independent signals counts one fact three times and reliably reaches the threshold — which
is how ~90 Cloudflare WARP sign-ins became flags in a single backfill with none of them
suspicious. When RDAP classifies the netblock as an anonymizer, the novelty of the exit
node scores once and lightly. Everything the VPN does not explain — Google's own verdict,
a relayable MFA challenge passed, a filter created — still scores in full, which is what
stops a VPN being a hiding place. **ASN alone cannot decide this:** AS13335 is Cloudflare,
which carries both WARP and attacker proxying. RDAP names the registered owner; the ASN
list is only the fallback for when it cannot.

**On the district network lowers risk, like a passkey.** A sign-in from `districtIpPrefix`
is somebody in a building behind the firewall, and a new /24 inside that range is a new
VLAN, not an intrusion — so the novelty trio is suppressed and the score drops 25. It is
not a free pass: Google's suspicious verdict and sensitive Gmail actions still score in
full, because a compromised district machine or a malicious insider is exactly the case
where "it came from inside" is the wrong conclusion.

**Passkeys lower risk, they do not raise it.** Two staff were both flagged suspicious by
Google and both used passkeys, which cannot be relayed. Score
−60.

**Carrier geolocation is not travel.** AT&T Mobility IPv6 (AS7018) geolocates to Texas
wherever the handset is, and consumer ISPs geolocate to the nearest metro hub, often in the
next state. Surface these for a phone call; never auto-remediate on them.

**`Allowing an app access to Google data` is routine OAuth consent** — 30 of 31 risky-action
events. Only `Access sensitive Gmail action (…filters…)` mattered, and it fired exactly once,
on the one account genuinely taken over.

## Codebase rules

- **Cross-instance state pins to `globalThis`.** `instrumentation.ts` and route handlers do
  not reliably share a module instance. A second worker runs every job twice — for a SWEEP
  that means trashing mail twice and racing its own verify.
- **Write files in binary mode.** `io.open(p,'w')` in Python is text mode on Windows and
  silently converts LF to CRLF. A CRLF shebang fails as `bash\r: command not found`, and
  CRLF on `set -euo pipefail` makes it an invalid option name — the script then runs on
  **without** strict mode. `.gitattributes` pins `eol=lf`.
- **Never trust a piped exit code.** `cmd | tail` reports tail's status.
- **An error handler must not be able to throw.** `catch (e) { ... (e as Error).message.slice(0, 300) }`
  looks fine and is a trap: `catch` receives `unknown`, and when the thrown value has no
  `message` the `.slice` throws from inside the handler. The new TypeError then replaces
  the original failure and propagates out of the function that existed to report it. The
  KnowBe4 sync failed ten consecutive scheduled runs recording
  `Cannot read properties of undefined (reading 'slice')` — which names no system, no host
  and no cause, because the real error was destroyed by the code describing it. Use
  `errText()` from `src/lib/errors.ts`. Reading a property is also code: a getter can
  throw, so `errText` guards every access and wraps its own body.
- **Never leave a child process's stderr as an unread pipe.** GAM writes one progress line
  per mailbox to stderr. Across 1,363 mailboxes that overflows the 64KB pipe buffer and GAM
  blocks forever on the write, while the parent waits on stdout that never arrives. It does
  not look like a deadlock — it looks like a slow scan. Diagnose with CPU time vs elapsed:
  8 seconds of CPU across 21 minutes of wall-clock, state `S`, is a blocked write. Either
  drain it (`child.stderr.on('data', …)`), pipe it to a file as `gam.ts` does, or pass
  `stdio: ['ignore', 'pipe', 'inherit']`. Bare `spawn(cmd, args)` pipes stderr by default,
  so omitting `stdio` is the bug.
- **No district data or credentials in tracked files.** This repository is public. Domains,
addresses, IP ranges, hostnames and people's names belong in the database (entered through
the setup wizard) or in the gitignored `private/` directory — never in code, comments,
tests or docs. Tests use `example.org` / `example.edu` and invented names.
