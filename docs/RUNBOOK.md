# Incident runbook

What to do, in order, for the three things Warden is built to handle. Everything here goes
through the console and is audited; nothing is automatic.

Roles: **ANALYST** reads, **RESPONDER** can sweep and run account actions, **ADMIN** can do
everything plus manage users and quarantine.

---

## 1. A reported phish (Phish Alert Button / forwarded mail)

1. **Read the report** on `/reports`. If Claude triage is on, it suggests a lure phrase and a
   scope query — a suggestion, never an action.
2. **Scope** (`/scope`): search on a distinctive **lure phrase**, with `in:anywhere`. Do **not**
   scope on the sender alone — a compromised partner account sends real mail too. The scope is
   read-only and shows how many mailboxes hold copies.
3. **Contain:**
   - For a campaign, **Sweep** from the scope result (type SWEEP). It trashes matching mail
     (recoverable), labels it, spares responder copies, and auto-queues a VERIFY.
   - For a handful of exact messages, use **Pick exact messages to label & Trash** on the scope
     result — ticks the messages and trashes them by id, no query needed.
4. **Verify.** Every sweep auto-runs a VERIFY. Read it: `CLEAN` means nothing survived outside
   Trash; `INCONCLUSIVE` means GAM did not finish — treat it as "not clean" and re-run.
5. **Reassure the reporter.** They did the right thing; the Phish Alert copy is the record.

> A zero-result scope is a reason to re-read the query, never a reason to sweep. Gmail cannot
> reliably match a bare domain inside a URL — scope on lure text, confirm payloads by body.

## 2. A compromised account (confirmed takeover)

Order matters — evict the session before resetting, or the attacker's live session keeps going.

1. **Account check** (`/accounts` → the mailbox, or from a sign-in flag): enumerates filters,
   forwarding, forwarding addresses, delegates, app passwords, and OAuth grants — the things
   that **survive a password reset**.
2. **Evict**, from the account-check job page (RESPONDER/ADMIN, typed-mailbox confirm):
   1. **Force sign-out** — revokes active sessions (the attacker is logged out now).
   2. **Reset password** — new random password, shown once here.
   3. **Revoke app passwords & OAuth tokens** (deprovision) — the token persistence a reset
      alone leaves behind.
3. **Remove persistence the check flagged.** Deleting a hostile **filter**, **forwarding**, or
   **delegate** is being added as a one-click action; until it ships, remove them by hand:
   `sudo -u warden -H /opt/gam7/gam user <mailbox> delete filter <id>`,
   `... forward off`, `... delete forwardingaddress <addr>`, `... delete delegate <email>`.
   Re-run the account check to confirm it is clean.
4. **Sweep any mail the attacker sent** (scope → sweep, as in §1) if they sent from the mailbox.
5. **Hand the account back.** Give the one-time password to the real user over a trusted channel.
6. **Suspend** instead of reset only if you need the account frozen (e.g. during HR/legal review).

## 3. A risky sign-in (sign-in risk queue)

1. **Triage** on `/risk`. The score and reasons say why it flagged (new network, foreign,
   passed MFA challenge, sensitive Gmail action). Carrier geolocation and VPNs are for a phone
   call, not auto-remediation.
2. **Ask the person.** If staff verification is on, Warden emails "was this you?" — a NO, or the
   email being deleted/filtered within minutes, is an alarm; a YES lowers the score.
3. **If compromised,** run §2. **If benign,** mark it so the queue stays readable. Student VPN
   noise has a one-click bulk dismiss on the Students tab.

---

## After any incident

- The **audit log** (`/audit`) has every scope, sweep, account action, settings change, and
  sign-in, with who and when. It is append-only by convention — copy rows out for a case file.
- Swept mail stays in **Trash** (recoverable) for 30 days; that is your evidence window.
- If you changed settings or added responders during the incident, review them afterwards.

## When something will not run

- **"Sweep refused: scopes on sender only"** — add a subject, a quoted lure phrase, or a
  message id; or use *Pick exact messages* instead.
- **"Destructive operations are disabled"** — sweeps need `WARDEN_ALLOW_DESTRUCTIVE=1` in the
  root-owned systemd drop-in. This is deliberately not a console setting.
- **An account action says role** — ANALYST is read-only; a RESPONDER or ADMIN must run it. The
  job page names who to call.
