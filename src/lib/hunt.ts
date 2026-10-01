/**
 * Query building and hit attribution for the indicator hunt.
 *
 * Extracted from scripts/hunt-iocs.ts so it can be tested. The first version of this logic
 * produced 1,981 findings in a 45-day dry run, almost all of them wrong, in two distinct
 * ways that both look like working code:
 *
 *   1. An unscoped `from:` on a compromised partner-district account matched that person's
 *      ordinary mail — "Cross Country", "Weather Protocol for New Prairie", "2026 New
 *      Prairie Invite". The account was genuinely compromised for a few days and is a
 *      genuine colleague either side of that. Sender alone cannot tell the two apart. This
 *      is the same fact that makes `assertSweepSafe()` refuse a from:-only sweep.
 *
 *   2. Attribution fell back to "the first LURE_STRING in the list" when nothing matched,
 *      so every unrelated message came back labelled with an indicator from a different
 *      campaign. A wrong attribution is worse than no attribution: it sends an analyst
 *      after the wrong attack.
 *
 * Both are exercised below.
 */

export interface HuntableIoc {
  value: string;
  kind: string;
  firstSeen?: Date | null;
  /** Always present in the schema; the fallback anchor when firstSeen is null. */
  addedAt: Date;
}

/** Body matched a lure Gmail can see and the message CSV cannot. Never guess which one. */
export const UNATTRIBUTED = '(body match — indicator not determined)';

const DAY_MS = 86_400_000;

/** Gmail's after:/before: want yyyy/mm/dd. */
function gmailDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10).replace(/-/g, '/');
}

/**
 * One Gmail query term per indicator, to be OR-ed into a single query — GAM walks every
 * mailbox per invocation, so N separate queries would be N full passes over 1,300+
 * mailboxes.
 *
 * Every SENDER term carries a date window. There is deliberately no branch that emits a
 * bare `from:`, including when firstSeen is null, because that is the case that produced
 * the false positives.
 */
export function huntTerms(iocs: HuntableIoc[], windowDays: number): string[] {
  return iocs.map((i) => {
    if (i.kind !== 'SENDER') return `"${i.value.replace(/"/g, '')}"`;
    const anchor = (i.firstSeen ?? i.addedAt).getTime();
    return `(from:${i.value} after:${gmailDay(anchor - windowDays * DAY_MS)} before:${gmailDay(anchor + windowDays * DAY_MS)})`;
  });
}

/**
 * Which indicator explains this message, or null if it cannot be shown.
 *
 * Gmail matches LURE_STRING against the message BODY, which the `print messages` CSV does
 * not contain. A subject check is therefore the only attribution available, and it often
 * finds nothing — that result is "unattributed", never a guess.
 */
export function attribute(
  from: string,
  subject: string | null,
  iocs: HuntableIoc[]
): HuntableIoc | null {
  const f = from.toLowerCase();
  const s = (subject ?? '').toLowerCase();
  return (
    iocs.find((x) => x.kind === 'SENDER' && f.includes(x.value.toLowerCase())) ??
    iocs.find((x) => x.kind === 'LURE_STRING' && s.includes(x.value.toLowerCase())) ??
    null
  );
}

/**
 * What a hunt must never count as a hit: Warden's own notifications and responder traffic.
 *
 * A lure string hunt for "Inv 80044710620" returned three "hits" on 2026-09-29 — Warden's
 * own alert emails to two admins, which quote the subject, and the reporter's
 * [Phish Alert] copy. Sweeps have always excluded these; the hunt did not, so the console
 * reported its own warnings as the campaign spreading.
 *
 * Deliberately NOT a blanket `-from:<staff domain>` the way sweeps use. A hunt that
 * ignores internal senders cannot see a compromised staff account sending the lure onward
 * — which is precisely the escalation worth finding. Only Warden's own address and the
 * protected responder subjects are excluded.
 */
export function huntExclusions(opts: { wardenFrom?: string | null; protectedSubjects: string[] }): string {
  const parts: string[] = [];
  const addr = opts.wardenFrom?.match(/[^\s<>"]+@[^\s<>"]+/)?.[0];
  if (addr) parts.push(`-from:${addr}`);
  for (const s of opts.protectedSubjects) parts.push(`-subject:"${s.replace(/"/g, '')}"`);
  return parts.join(' ');
}

/** Belt and braces on the result rows, in case Gmail's matching is looser than the query. */
export function isOwnTraffic(
  row: { from: string; subject: string | null },
  opts: { wardenFrom?: string | null; protectedSubjects: string[] }
): boolean {
  const addr = opts.wardenFrom?.match(/[^\s<>"]+@[^\s<>"]+/)?.[0]?.toLowerCase();
  if (addr && row.from.toLowerCase().includes(addr)) return true;
  const subj = (row.subject ?? '').toLowerCase();
  if (/\[internal\]\s*warden:/i.test(subj)) return true;
  return opts.protectedSubjects.some((p) => subj.includes(p.toLowerCase()));
}
