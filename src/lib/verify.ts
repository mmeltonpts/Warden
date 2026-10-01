/**
 * Pure logic for the two sign-in follow-ups, kept apart from GAM and the database so the
 * rules can be tested on their own:
 *
 *   1. Staff verification — a "was this you?" email after a risky VPN or foreign sign-in,
 *      plus the reading of the reply and of what happened to the email in the mailbox.
 *   2. Student VPN notices — routing a student sign-in to the right building's administrator.
 */
import { randomBytes } from 'node:crypto';

// ─── staff verification ───────────────────────────────────────────────────────

/** A short code placed in the subject, matched back when the person replies. */
export function makeCode(): string {
  return `SV-${randomBytes(4).toString('hex')}`;
}

/** Pull the code back out of a reply subject like "Re: … [SV-7bq2kf1a]". */
export function codeFromSubject(subject: string | null | undefined): string | null {
  // Codes we issue are hex, but a reply subject can be re-encoded or lower-cased by the
  // sender's client, so match any 8-char alphanumeric tail and normalise it.
  return String(subject ?? '').match(/\bSV-[0-9a-z]{8}\b/i)?.[0].toUpperCase() ?? null;
}

/**
 * Does a risk flag warrant an email? Only staff, only at or above the configured score, and
 * (by default) only for a VPN/anonymizer or a foreign sign-in — the cases a person can
 * actually answer. A flag whose only reason is "on the district network" is not one of them.
 */
export function qualifiesForVerify(
  flag: { score: number; reasons: string[] },
  opts: { minScore: number; onlyVpnOrForeign: boolean }
): boolean {
  if (flag.score < opts.minScore) return false;
  if (!opts.onlyVpnOrForeign) return true;
  const hay = flag.reasons.join(' ').toLowerCase();
  return /vpn|privacy relay|anonymiz|outside|foreign|out of country|out-of-country/.test(hay);
}

/**
 * Read a reply. YES only counts when the person actually says it — an empty or quoted-only
 * reply is left as no decision rather than guessed. NO wins over YES if somehow both appear,
 * because a denial is the safety-critical answer.
 */
export function parseReplyDecision(body: string | null | undefined): 'yes' | 'no' | null {
  // Only the new text, above the quoted original, carries the answer.
  const top = String(body ?? '')
    .split(/^\s*(?:on .*wrote:|-{2,} ?original message|_{5,}|from:\s)/im)[0]
    .toLowerCase();
  const no = /\b(no|not me|wasn'?t me|was not me|didn'?t|did not|nope|never)\b/.test(top);
  const yes = /\b(yes|yep|yeah|that was me|it was me|me|confirm|correct|mine)\b/.test(top);
  if (no) return 'no';
  if (yes) return 'yes';
  return null;
}

/**
 * What the labels on the SENT email say. Warden delivers it to the inbox; a legitimate owner
 * leaves it there. If it is in Trash or Spam, or has been archived away from the inbox, or
 * cannot be found at all, within the watch window, that is the fingerprint of an auto-delete
 * rule an attacker added — the whole reason the subject uses words such rules target.
 *
 * `labels` is what GAM reports for the message, or null when the message is not found.
 */
export function hiddenVerdict(labels: string[] | null): { hidden: boolean; detail: string } {
  if (labels === null) return { hidden: true, detail: 'the email is gone from the mailbox entirely' };
  const set = new Set(labels.map((l) => l.toUpperCase()));
  if (set.has('TRASH')) return { hidden: true, detail: 'the email was moved to Trash' };
  if (set.has('SPAM')) return { hidden: true, detail: 'the email was moved to Spam' };
  if (!set.has('INBOX')) return { hidden: true, detail: 'the email was archived out of the inbox' };
  return { hidden: false, detail: set.has('UNREAD') ? 'still in the inbox, unread' : 'still in the inbox, read' };
}

/** When to re-check the mailbox after sending, in minutes. "2,10,30" → [2,10,30]. */
export function checkSchedule(csv: string | null | undefined): number[] {
  return String(csv ?? '')
    .split(/[,\s]+/)
    .map((x) => Number(x.trim()))
    .filter((n) => Number.isFinite(n) && n > 0)
    .slice(0, 12);
}

/** The next check that is due: the smallest scheduled offset later than the last check done. */
export function nextCheckDue(
  sentAt: Date,
  schedule: number[],
  lastCheckedAt: Date | null,
  now: Date
): boolean {
  const elapsedMin = (now.getTime() - sentAt.getTime()) / 60_000;
  const lastMin = lastCheckedAt ? (lastCheckedAt.getTime() - sentAt.getTime()) / 60_000 : -1;
  return schedule.some((m) => m <= elapsedMin && m > lastMin);
}

/** Past the last scheduled check with no decision → close as EXPIRED. */
export function pastLastCheck(sentAt: Date, schedule: number[], now: Date): boolean {
  const last = schedule.length ? Math.max(...schedule) : 0;
  return (now.getTime() - sentAt.getTime()) / 60_000 > last;
}

/**
 * The email. No links: our own training tells people not to click links in security mail, so
 * this asks for a reply or a phone call instead. {placeholders} are filled from the sign-in.
 */
export function renderVerifyEmail(
  template: { subject: string; body: string },
  v: { displayName: string; code: string; when: string; where: string; replyMailbox: string; helpdesk: string }
): { subject: string; text: string } {
  const fill = (s: string) =>
    s
      .replaceAll('{name}', v.displayName)
      .replaceAll('{code}', v.code)
      .replaceAll('{when}', v.when)
      .replaceAll('{where}', v.where)
      .replaceAll('{reply}', v.replyMailbox)
      .replaceAll('{helpdesk}', v.helpdesk);
  // The code is forced into the subject even if the template forgets it, so a reply can be
  // matched back to this sign-in.
  let subject = fill(template.subject);
  if (!/\bSV-[0-9a-f]{8}\b/i.test(subject)) subject = `${subject} [${v.code}]`;
  return { subject, text: fill(template.body) };
}

// ─── student VPN notices ──────────────────────────────────────────────────────

/**
 * Route a student's Org Unit to a building administrator. Mapping is one rule per line,
 * "OU-prefix = email", e.g. "/Student Accounts/PHS = phs.admin@…". The LONGEST matching
 * prefix wins, so a grade-level override sits above a building default.
 */
export function parseBuildingMap(text: string | null | undefined): Array<{ prefix: string; email: string }> {
  return String(text ?? '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && l.includes('=') && !l.startsWith('#'))
    .map((l) => {
      const i = l.indexOf('=');
      return { prefix: l.slice(0, i).trim(), email: l.slice(i + 1).trim() };
    })
    .filter((r) => r.prefix && r.email);
}

export function buildingAdminFor(
  ouPath: string | null | undefined,
  map: Array<{ prefix: string; email: string }>
): string | null {
  const ou = String(ouPath ?? '');
  let best: { prefix: string; email: string } | null = null;
  for (const r of map) {
    if ((ou === r.prefix || ou.startsWith(r.prefix.replace(/\/+$/, '') + '/')) &&
        (!best || r.prefix.length > best.prefix.length)) {
      best = r;
    }
  }
  return best?.email ?? null;
}

/**
 * Was the sign-in during school hours? A rough local-time window, because the point is only
 * to tell "on a school device during class" apart from "at home in the evening" for the
 * administrator's triage, not to timestamp anything to the minute.
 *
 * `offsetMinutes` is the district's UTC offset (e.g. Central Daylight is -300). Days are
 * 0=Sun..6=Sat. Window is local "HH:MM-HH:MM".
 */
export function duringSchoolHours(
  tsUtc: Date,
  opts: { offsetMinutes: number; days: number[]; window: string }
): boolean {
  const local = new Date(tsUtc.getTime() + opts.offsetMinutes * 60_000);
  const day = local.getUTCDay();
  if (!opts.days.includes(day)) return false;
  const m = opts.window.match(/^(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$/);
  if (!m) return true; // unparseable window: do not hide the row, let the admin judge
  const mins = local.getUTCHours() * 60 + local.getUTCMinutes();
  const start = Number(m[1]) * 60 + Number(m[2]);
  const end = Number(m[3]) * 60 + Number(m[4]);
  return mins >= start && mins <= end;
}
