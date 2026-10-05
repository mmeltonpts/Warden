/**
 * Staff phish-report ingestion.
 *
 * The Phish Alert Button forwards a reported message to a mailbox. Warden reads that
 * mailbox through GAM, pulls the ORIGINAL sender / subject / payload hosts out of the
 * forwarded copy, and builds a triage queue.
 *
 * Why this matters more than any other feature here: between 2026-03 and 2026-09,
 * 504 reports from 190 staff went to a decommissioned PhishER tenant. Staff detected
 * the Adobe campaign (71 reports, 61 people, three months) correctly and nobody saw it.
 * The detection was never the weak link — the pipeline was.
 *
 * Parsing note: the PAB forwards the original with its headers indented inside the body,
 * and (when "Send email headers as TXT attachments" is on) attaches the full header set.
 * The body form is what we parse, because it is present regardless of that setting.
 */

export interface ParsedReport {
  originalSender?: string;
  originalSubject?: string;
  originalTo?: string;
  payloadHosts: string[];
  /** Full URLs with redirect wrappers already unwrapped. Rendered defanged, never linked. */
  payloadUrls?: string[];
}

/**
 * Defang a URL for display.
 *
 * Every URL in this queue is, by assumption, hostile. Rendering one as a live anchor in an
 * IR console puts a one-click payload in front of the person whose job is to investigate it,
 * and browsers preload and prefetch. `hxxps://evil[.]example` is inert, still readable, and
 * still copyable for anyone who genuinely needs to detonate it somewhere safe.
 */
export function defang(url: string): string {
  return url.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

/** Hosts that carry no signal — the reporting chain and common legitimate infrastructure. */
const IGNORE_HOSTS =
  /^(.*\.)?(google|gstatic|googleusercontent|knowbe4|phisher\.knowbe4|w3|schema|microsoft|office|outlook|gmail)\./i;

/**
 * Also ignored: the district's own domains (from Settings), because every forwarded report
 * carries links back to them in signatures and footers. Passed in rather than hardcoded so
 * the same build serves any district.
 */
/**
 * Google surfaces attackers actually host landing pages and forms on. These match the broad
 * `google` ignore above but ARE payloads — a phishing form on `docs.google.com/forms/...` or a
 * fake login on `sites.google.com/view/...` is exactly what a report is about — so they are
 * carved back out of the ignore. Profile-image and UI noise on other google hosts stays ignored.
 */
const GOOGLE_PAYLOAD_HOSTS = /^(docs|sites|drive|script)\.google\.com$|^forms\.gle$/i;

function ignoredHost(h: string, ownDomains: string[]): boolean {
  if (GOOGLE_PAYLOAD_HOSTS.test(h)) return false;
  if (IGNORE_HOSTS.test(h + '.')) return true;
  return ownDomains.some((d) => d && (h === d.toLowerCase() || h.endsWith('.' + d.toLowerCase())));
}

/**
 * Unwrap google.com/url?q= and similar click-trackers to the real destination.
 *
 * `depth` stops a self-referential or cyclic wrapper (`?url=…?url=…`) from recursing forever —
 * a crafted link must never be able to overflow the stack of the thing parsing it. Five hops is
 * far more nesting than any legitimate tracker uses.
 */
export function unwrapRedirect(url: string, depth = 0): string {
  if (depth >= 5) return url;
  try {
    const u = new URL(url);
    if (/(^|\.)google\.[a-z.]+$/i.test(u.hostname) && u.pathname === '/url') {
      const q = u.searchParams.get('q') ?? u.searchParams.get('url');
      if (q) return unwrapRedirect(decodeURIComponent(q), depth + 1);
    }
    // Generic single-hop trackers that put the target in a query parameter.
    for (const k of ['u', 'url', 'target', 'redirect', 'r']) {
      const v = u.searchParams.get(k);
      if (v && /^https?:\/\//i.test(v)) return unwrapRedirect(decodeURIComponent(v), depth + 1);
    }
    return url;
  } catch {
    return url;
  }
}

/**
 * Extract candidate payload hosts.
 *
 * Redirect wrappers are unwrapped BEFORE filtering. A payload behind
 * `google.com/url?q=` was invisible to a filter that excluded "google", and that
 * mistake let a real phish through a verification that reported clean.
 */
export function extractPayloadHosts(body: string, ownDomains: string[] = []): string[] {
  const out = new Set<string>();
  for (const m of body.matchAll(/https?:\/\/[^\s"'<>)\]]+/gi)) {
    const final = unwrapRedirect(m[0]);
    try {
      const h = new URL(final).hostname.toLowerCase();
      if (!ignoredHost(h, ownDomains)) out.add(h);
    } catch {
      /* not parseable */
    }
  }
  return [...out].slice(0, 12);
}

/**
 * The same extraction, but keeping the whole URL rather than just the host.
 *
 * A host tells you which campaign this is; the full path and query tell you what the
 * attacker wanted — which brand is being impersonated, whether the victim's address was
 * pre-filled into the landing page, what the redirect chain was. That is the difference
 * between classifying a report and understanding it.
 */
export function extractPayloadUrls(body: string, ownDomains: string[] = []): string[] {
  const out = new Set<string>();
  for (const m of body.matchAll(/https?:\/\/[^\s"'<>)\]]+/gi)) {
    const final = unwrapRedirect(m[0]);
    try {
      const h = new URL(final).hostname.toLowerCase();
      if (!ignoredHost(h, ownDomains)) out.add(final.slice(0, 500));
    } catch {
      /* not parseable */
    }
  }
  return [...out].slice(0, 25);
}

/**
 * Pull the original message's headers out of a forwarded PAB report.
 *
 * The report's own From/To are the reporter and the report mailbox; the original's are
 * nested further down. We therefore take the LAST plausible From: in the body, and never
 * accept an internal address as the original sender unless nothing else is present —
 * a compromised internal account is a real case, but the reporter's own address appearing
 * first is far more common.
 */
export function parseReportBody(body: string, reporter: string, ownDomains: string[] = []): ParsedReport {
  const froms = [...body.matchAll(/^\s*From:\s*(.+)$/gim)].map((m) => m[1].trim());
  const subjects = [...body.matchAll(/^\s*Subject:\s*(.+)$/gim)].map((m) => m[1].trim());

  const addrOf = (s: string) => (s.match(/[\w.\-+]+@[\w.\-]+/) ?? [])[0]?.toLowerCase();

  let originalSender: string | undefined;
  for (const f of froms) {
    const a = addrOf(f);
    if (!a || a === reporter.toLowerCase()) continue;
    originalSender = a; // keep scanning; the deepest nested From wins
  }
  if (!originalSender && froms.length) originalSender = addrOf(froms[froms.length - 1]);

  const originalSubject = subjects
    .map((s) => s.replace(/^\[Phish Alert\]\s*/i, '').trim())
    .filter(Boolean)
    .pop();

  // The original's To: is the deepest one, same reasoning as From: — the report's own To:
  // is the reporting mailbox. `undisclosed-recipients:;` here is a strong signal on its own.
  const tos = [...body.matchAll(/^\s*To:\s*(.+)$/gim)].map((m) => m[1].trim());
  const originalTo = tos.length ? tos[tos.length - 1].slice(0, 300) : undefined;

  return {
    originalSender,
    originalSubject,
    originalTo,
    payloadHosts: extractPayloadHosts(body, ownDomains),
    payloadUrls: extractPayloadUrls(body, ownDomains)
  };
}

/**
 * Suppression check against the KNOWN_GOOD list.
 *
 * Matches on sender OR subject. A recurring notice from the district's own background-check
 * vendor was reported by one person four times in a month. Without this, every recurrence costs triage and teaches people that
 * reporting achieves nothing.
 */
export function isKnownGood(
  parsed: ParsedReport,
  knownGood: string[]
): { suppressed: boolean; matched?: string } {
  const hay = [parsed.originalSender ?? '', parsed.originalSubject ?? ''].map((x) => x.toLowerCase());
  for (const k of knownGood) {
    const needle = k.toLowerCase();
    if (hay.some((h) => h && (h === needle || h.includes(needle)))) {
      return { suppressed: true, matched: k };
    }
  }
  return { suppressed: false };
}

/**
 * Group reports into campaigns.
 *
 * Sender alone is wrong — this attacker rotates senders every day or two against a fixed
 * payload (nine accounts, one `downloaddocument.tech`). Payload host is the strongest key,
 * then normalised subject, then sender.
 */
export function campaignKey(p: ParsedReport): string {
  if (p.payloadHosts.length) return `host:${p.payloadHosts.slice().sort()[0]}`;
  if (p.originalSubject) {
    const norm = stripSubjectTags(p.originalSubject)
      .toLowerCase()
      .replace(/^\s*(re|fwd?)\s*:\s*/g, '')
      .replace(/\[(external sender|internal)\]\s*/g, '')
      .replace(/[^a-z0-9 ]+/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (norm) return `subj:${norm.slice(0, 60)}`;
  }
  return `from:${p.originalSender ?? 'unknown'}`;
}

/**
 * Gmail query for the report mailboxes.
 *
 * A bare domain MUST NOT be expressed as `to:`. Gmail does not match the `to:` operator
 * against a domain alone: `to:phisher.knowbe4.com` returned ZERO against 504 messages
 * provably addressed to `a42a9d34-…@phisher.knowbe4.com`. The free-text term `"domain"`
 * matches all 504.
 *
 * This is the same trap as the bare-domain-in-a-URL rule in CLAUDE.md, in a different
 * operator, and it cost a full 180-day scan to find twice.
 */
/**
 * Strip leading bracketed tags from a subject.
 *
 * Mail arrives already tagged by the gateway — `[External Sender]`, `[Internal]`,
 * `[Phish Alert]` — and districts add their own with content-compliance rules, such as
 * `[DISTRICT CONTACT FORM]` to mark website contact-form notifications that staff keep
 * reporting as phishing.
 *
 * Any of those must be removed before grouping or de-duplicating, or one campaign splits
 * into two the day a new rule is switched on: the tagged copies stop matching the untagged
 * ones and the count on the Reports page silently halves.
 *
 * Deliberately generic rather than a list of known tags. A district can add a tag tomorrow
 * without editing code, which is the whole point — and stripping an unfamiliar tag only
 * ever affects grouping, never the subject shown on screen.
 */
export function stripSubjectTags(subject: string): string {
  return subject.replace(/^\s*(?:\[[^\]]{1,40}\]\s*)+/, '').trim();
}

/**
 * A stable identity for "the same message, reported by the same person".
 *
 * One person can report one message twice without meaning to: the Phish Alert Button
 * forwards it to a mailbox, and Gmail's own "Report phishing" raises an Alert Center alert.
 * Warden reads both channels, so the same event landed in the queue twice and an analyst
 * was asked to judge it twice.
 *
 * Deliberately keyed on the REPORTER as well as the message. Forty different people
 * reporting one campaign is forty reports, and that count is the most useful number on the
 * page — that is not duplication. One person reporting one message through two channels is.
 */
export function dedupeKey(
  reporter: string,
  sender: string | null | undefined,
  subject: string | null | undefined
): string {
  const s = stripSubjectTags(subject ?? '')
    .toLowerCase()
    .replace(/^\s*(re|fwd?)\s*:\s*/g, '')
    .replace(/[^a-z0-9 ]+/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
  return `${reporter.toLowerCase()}|${(sender ?? '').toLowerCase()}|${s}`;
}

/**
 * Decide whether to warn that report ingestion has gone quiet.
 *
 * A misconfigured report address — a typo, a mailbox renamed to a group — produces a CLEAN
 * zero that no error check catches: the scan succeeds and matches nothing. (This is exactly
 * what happened on 2026-10-01: a misspelled report address, four days of "0 new" that read as
 * calm.) So compare a recent window against a baseline: if nothing has arrived recently but the
 * district normally reports steadily, the address is probably pointing at the wrong place.
 *
 * Guarded so a genuinely new or low-traffic install does not cry wolf: the baseline must show
 * real, sustained reporting before silence is treated as a fault.
 */
export interface QuietCheck {
  recentCount: number;
  baselineCount: number;
  baselineDays: number;
}
export function shouldAlertQuiet(c: QuietCheck): boolean {
  if (c.recentCount > 0) return false;
  const perDay = c.baselineDays > 0 ? c.baselineCount / c.baselineDays : 0;
  return c.baselineCount >= 10 && perDay >= 0.5;
}

export function reportQuery(addresses: string[], lookbackDays: number): string {
  const terms = addresses
    .filter(Boolean)
    .map((a) => (a.includes('@') ? `to:${a}` : `"${a}"`));
  return `(${terms.join(' OR ')}) in:anywhere newer_than:${lookbackDays}d`;
}
