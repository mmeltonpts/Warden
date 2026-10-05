/**
 * Forwarding & delegate watch (pure logic).
 *
 * Auto-forwarding to an outside address and an outside delegate are the classic BEC
 * persistence: they survive a password reset and quietly copy or expose mail. The account
 * check already finds them on ONE mailbox on demand; this watches EVERY mailbox on a schedule,
 * so an attacker who set forwarding without ever tripping a risky sign-in is still caught.
 *
 * The signal is EXTERNAL target. Internal forwarding and internal delegates are ordinary
 * (a shared role mailbox, an assistant who manages a principal's calendar), so they are
 * recorded but not alarmed. A target outside the district's own domains is the exfil shape.
 *
 * Pure: no GAM, no DB. The scan script does the I/O and passes the GAM output in.
 */
import { splitCsv } from './gmaillog';

export type PersistKind = 'forward' | 'forwardingaddress' | 'delegate';

export interface PersistItem {
  mailbox: string;
  kind: PersistKind;
  /** The forwarding address or delegate email. */
  target: string;
  external: boolean;
  /** verificationStatus / delegationStatus / forward disposition — context for the UI. */
  detail?: string;
}

/**
 * Is an address outside the district's own domains? A domain matches when it equals a
 * configured domain or is a subdomain of one. An unparseable address is treated as NOT
 * external, so a malformed row cannot manufacture an alarm.
 */
export function isExternal(addr: string, domains: string[]): boolean {
  const d = addr.toLowerCase().match(/@([a-z0-9.-]+)$/)?.[1];
  if (!d) return false;
  const own = domains.map((x) => x.trim().toLowerCase()).filter(Boolean);
  return !own.some((dom) => d === dom || d.endsWith('.' + dom));
}

function headerIndex(header: string[], ...names: RegExp[]): number {
  for (const re of names) {
    const i = header.findIndex((h) => re.test(h.trim()));
    if (i >= 0) return i;
  }
  return -1;
}

/** Parse `gam all users print forwardingaddresses` — User,forwardingEmail,verificationStatus. */
export function parseForwardingAddresses(csv: string, domains: string[]): PersistItem[] {
  return parseCsvItems(csv, 'forwardingaddress', domains, /^forwardingEmail$|address/i, /verificationStatus|status/i);
}

/** Parse `gam all users print delegates` — User,delegateAddress,delegationStatus. */
export function parseDelegates(csv: string, domains: string[]): PersistItem[] {
  return parseCsvItems(csv, 'delegate', domains, /^delegateAddress$|delegate|address/i, /delegationStatus|status/i);
}

function parseCsvItems(
  csv: string,
  kind: PersistKind,
  domains: string[],
  targetCol: RegExp,
  statusCol: RegExp
): PersistItem[] {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = splitCsv(lines[0]).map((h) => h.trim());
  const iUser = headerIndex(header, /^User$|primaryEmail|^email$/i);
  const iTarget = headerIndex(header, targetCol);
  const iStatus = headerIndex(header, statusCol);
  if (iUser < 0 || iTarget < 0) return [];
  const out: PersistItem[] = [];
  for (const line of lines.slice(1)) {
    const f = splitCsv(line);
    const mailbox = (f[iUser] ?? '').trim().toLowerCase();
    const target = (f[iTarget] ?? '').trim().toLowerCase();
    if (!mailbox || !target || !target.includes('@')) continue;
    out.push({
      mailbox,
      kind,
      target,
      external: isExternal(target, domains),
      detail: iStatus >= 0 ? f[iStatus]?.trim() || undefined : undefined
    });
  }
  return out;
}

/**
 * Parse `gam all users show forward` text. One line per user:
 *   `User: a@x, Forward Enabled: True, Forwarding Address: b@y, Action: KEEP`
 * Only lines with forwarding ENABLED and an address yield an item.
 */
export function parseActiveForward(text: string, domains: string[]): PersistItem[] {
  const out: PersistItem[] = [];
  for (const line of text.split(/\r?\n/)) {
    const mailbox = line.match(/User:\s*([^\s,]+)/)?.[1]?.toLowerCase();
    if (!mailbox || !/Forward Enabled:\s*True/i.test(line)) continue;
    const target = line.match(/Forwarding Address:\s*([^\s,]+)/i)?.[1]?.toLowerCase();
    if (!target || !target.includes('@')) continue;
    out.push({
      mailbox,
      kind: 'forward',
      target,
      external: isExternal(target, domains),
      detail: line.match(/Action:\s*([^\s,]+)/i)?.[1]
    });
  }
  return out;
}

const KIND_LABEL: Record<PersistKind, string> = {
  forward: 'Auto-forwarding is ON',
  forwardingaddress: 'A forwarding address is registered',
  delegate: 'A delegate can open this mailbox'
};

/** Human reasons for a flagged item. External targets lead; the kind explains what it is. */
export function itemReasons(item: PersistItem): string[] {
  const reasons = [`${KIND_LABEL[item.kind]} → ${item.target}`];
  if (item.external) {
    reasons.push(
      'The destination is OUTSIDE the district — the shape of mail exfiltration; confirm the user set this up'
    );
  } else {
    reasons.push('Internal destination — ordinary for a shared role or an assistant, but new, so noted');
  }
  if (item.detail) reasons.push(`Status: ${item.detail}`);
  return reasons;
}
