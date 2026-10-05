/**
 * Mass-mail / exfil detector (pure logic).
 *
 * The Gmail delivery log cannot be scanned tenant-wide cheaply (flattening every row OOM'd a
 * 4 GB heap), so this does not hunt blindly. It checks the SENT mail of the mailboxes that are
 * ALREADY suspect — an open sign-in risk flag, a new mail-capable OAuth grant, or a new
 * external forward — and asks the one question that turns suspicion into an incident: is this
 * account now sending to a lot of people? A compromised account that logged in oddly AND is
 * now blasting is an active exfil/BEC, not a maybe.
 *
 * Pure: no GAM, no DB. The scan script runs `gam user <mb> print messages query "in:sent …"`
 * and passes the CSV in.
 */
import { splitCsv } from './gmaillog';

const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;

export interface SentSummary {
  /** Number of sent messages in the window. */
  messages: number;
  /** Distinct recipient addresses across To/Cc. */
  recipients: string[];
  /** Distinct recipients outside the district's domains. */
  external: string[];
}

function isExternalAddr(addr: string, domains: string[]): boolean {
  const d = addr.toLowerCase().match(/@([a-z0-9.-]+)$/)?.[1];
  if (!d) return false;
  return !domains.map((x) => x.trim().toLowerCase()).filter(Boolean).some((dom) => d === dom || d.endsWith('.' + dom));
}

/**
 * Summarise `gam user <mb> print messages query "in:sent …" headers "To,Cc"`: count the
 * messages and the distinct (and distinct-external) recipients. Columns found BY NAME; an
 * empty/header-only CSV is zero messages, never an error disguised as calm (the scan script
 * throws on a non-zero GAM exit).
 */
export function summarizeSent(csv: string, domains: string[]): SentSummary {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return { messages: 0, recipients: [], external: [] };
  const header = splitCsv(lines[0]).map((h) => h.trim().toLowerCase());
  const cols = ['to', 'cc'].map((n) => header.indexOf(n)).filter((i) => i >= 0);
  const recips = new Set<string>();
  let messages = 0;
  for (const line of lines.slice(1)) {
    messages++;
    const f = splitCsv(line);
    for (const ci of cols) {
      const cell = f[ci] ?? '';
      for (const m of cell.match(EMAIL) ?? []) recips.add(m.toLowerCase());
    }
  }
  const recipients = [...recips];
  return { messages, recipients, external: recipients.filter((r) => isExternalAddr(r, domains)) };
}

export interface BlastThresholds {
  /** Sent-message count in the window that counts as a blast. */
  maxMessages: number;
  /** Distinct EXTERNAL recipients in the window that counts as a blast. */
  maxExternal: number;
}

/** A blast is a high sent-message count OR many distinct external recipients in the window. */
export function isBlast(s: SentSummary, t: BlastThresholds): boolean {
  return s.messages >= t.maxMessages || s.external.length >= t.maxExternal;
}

export function blastReasons(summary: SentSummary, windowHours: number, why: string): string[] {
  const reasons = [
    `Sent ${summary.messages} message${summary.messages === 1 ? '' : 's'} to ` +
      `${summary.recipients.length} recipient${summary.recipients.length === 1 ? '' : 's'} ` +
      `(${summary.external.length} external) in the last ${windowHours}h`,
    `This mailbox was already flagged: ${why}. A flagged account now sending in bulk is the ` +
      'mass-mail / exfiltration shape — treat as an active incident, not a maybe.'
  ];
  if (summary.external.length) {
    reasons.push(`External recipients include: ${summary.external.slice(0, 8).join(', ')}${summary.external.length > 8 ? ' …' : ''}`);
  }
  return reasons;
}
