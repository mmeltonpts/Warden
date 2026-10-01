/**
 * Parse `gam report gmail` — the Gmail delivery log from the Reports API.
 *
 * WHY THIS EXISTS
 *
 * Quarantined mail never reaches a mailbox, so every Warden scope — built on `print
 * messages` — is blind to it. A superintendent-impersonation BEC aimed at accounts payable
 * on 2026-09-29 was held by content-compliance rule 46 and was invisible to the console
 * that exists to track exactly that.
 *
 * Google offers no quarantine API. It does log every delivery decision, including the
 * rule that fired and whether it quarantined, and on this tenant that log is readable.
 *
 * THE FORMAT
 *
 * GAM flattens Google's nested name/value parameters into positional columns:
 *
 *   parameters.1.name                                         message_info
 *   parameters.1.messageValue.parameter.4.name                source
 *   parameters.1.messageValue.parameter.4.messageValue.parameter.0.name   address
 *   parameters.1.messageValue.parameter.4.messageValue.parameter.0.value  x@y.org
 *
 * Position numbers are NOT stable between rows — a parameter that is absent shifts the
 * rest. So this resolves every value to a dotted NAME path ("message_info.source.address")
 * and never trusts an index.
 */

export function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/** Split CSV text into records, honouring newlines inside quoted fields. */
export function csvRecords(text: string): string[][] {
  const recs: string[][] = [];
  let buf = '';
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') q = !q;
    if ((ch === '\n' || ch === '\r') && !q) {
      if (buf.trim()) recs.push(splitCsv(buf));
      buf = '';
      if (ch === '\r' && text[i + 1] === '\n') i++;
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) recs.push(splitCsv(buf));
  return recs;
}

/** One row → { "message_info.source.address": "...", ... } plus top-level columns. */
export function flattenRow(header: string[], row: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  const nameAt = new Map<string, string>(); // column prefix -> parameter name
  header.forEach((col, i) => {
    if (col.endsWith('.name') && row[i]) nameAt.set(col.slice(0, -5), row[i]);
  });

  const keyFor = (prefix: string): string | null => {
    // Every ancestor that is itself a named parameter contributes a segment.
    const parts: string[] = [];
    const segs = prefix.split('.');
    for (let n = 1; n <= segs.length; n++) {
      const p = segs.slice(0, n).join('.');
      const nm = nameAt.get(p);
      if (nm) parts.push(nm);
    }
    return parts.length ? parts.join('.') : null;
  };

  header.forEach((col, i) => {
    const v = row[i];
    if (!v) return;
    const m = col.match(/^(.*)\.(value|intValue|boolValue|multiValue(?:\.\d+)?)$/);
    if (!m) {
      if (!col.startsWith('parameters.')) out[col] = v;
      return;
    }
    const key = keyFor(m[1]);
    if (!key) return;
    out[key] = out[key] ? `${out[key]} | ${v}` : v;
  });
  return out;
}

export interface RuleHit {
  name: string;
  /** 'quarantine' when the consequence carries admin_quarantine_info. */
  quarantine: boolean;
  matched: string[];
}

export interface GmailLogEvent {
  msgId: string;
  time: Date;
  recipient: string | null;
  sender: string | null;
  subject: string | null;
  senderIp: string | null;
  attachments: number;
  linkDomains: string[];
  isSpam: boolean;
  rules: RuleHit[];
  quarantined: boolean;
}

function parseRules(json: string | undefined): RuleHit[] {
  if (!json) return [];
  try {
    const arr = JSON.parse(json) as Array<Record<string, unknown>>;
    return arr.map((r) => {
      const cons = (r.consequence as Array<Record<string, unknown>> | undefined) ?? [];
      return {
        name: String(r.rule_name ?? `rule ${r.rule_id ?? '?'}`),
        quarantine: cons.some((c) => c.admin_quarantine_info !== undefined),
        matched: ((r.string_match as Array<Record<string, unknown>> | undefined) ?? [])
          .map((s) => String(s.matched_string ?? ''))
          .filter(Boolean)
      };
    });
  } catch {
    return [];
  }
}

const pick = (f: Record<string, string>, ...keys: string[]) => {
  for (const k of keys) if (f[k]) return f[k];
  return null;
};

export function parseGmailLog(csv: string): GmailLogEvent[] {
  const recs = csvRecords(csv);
  if (recs.length < 2) return [];
  const header = recs[0];
  const out: GmailLogEvent[] = [];
  for (const row of recs.slice(1)) {
    const e = eventFromRow(header, row);
    if (e) out.push(e);
  }
  return out;
}

/**
 * Stream a GAM gmail report FILE, fully parsing only rows whose raw text contains `needle`.
 *
 * The first version read the report into a string and parsed every row. A 24-hour pull for
 * a 1,364-mailbox domain ran Node out of a 4 GB heap: hundreds of thousands of rows, each
 * with thousands of positional columns. The pre-filter is a substring test on the raw line,
 * so ~99.9% of rows are skipped for the cost of an indexOf and never flattened.
 *
 * Records may span physical lines when a quoted field (a subject) contains a newline, so
 * lines are joined while the quote count is odd.
 */
export async function scanGmailLogFile(
  file: string,
  needle: string,
  onEvent: (e: GmailLogEvent) => void | Promise<void>
): Promise<{ rows: number; matched: number }> {
  const { createReadStream } = await import('node:fs');
  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: createReadStream(file, 'utf8'), crlfDelay: Infinity });

  let header: string[] | null = null;
  let pending = '';
  let rows = 0;
  let matched = 0;
  const quotes = (s: string) => (s.match(/"/g)?.length ?? 0);

  for await (const line of rl) {
    pending = pending ? `${pending}\n${line}` : line;
    if (quotes(pending) % 2 === 1) continue; // inside a quoted field
    const rec = pending;
    pending = '';
    if (!header) { header = splitCsv(rec); continue; }
    rows++;
    if (!rec.includes(needle)) continue;
    const e = eventFromRow(header, splitCsv(rec));
    if (e) { matched++; await onEvent(e); }
  }
  return { rows, matched };
}

function eventFromRow(header: string[], row: string[]): GmailLogEvent | null {
  {
    const f = flattenRow(header, row);
    const msgId = pick(f, 'message_info.rfc2822_message_id');
    if (!msgId) return null;
    const rules = parseRules(pick(f, 'message_info.flattened_triggered_rule_info') ?? undefined);
    const tRaw = pick(f, 'id.time');
    const links = (pick(f, 'message_info.link_domain') ?? '')
      .split('|')
      .map((s) => s.trim())
      .filter((s) => s && !/^\d+$/.test(s));
    return {
      msgId: msgId.replace(/^<|>$/g, ''),
      time: tRaw ? new Date(tRaw) : new Date(0),
      recipient: pick(f, 'actor.email'),
      sender: pick(f, 'message_info.source.from_header_address', 'message_info.source.address'),
      subject: pick(f, 'message_info.subject'),
      senderIp: pick(f, 'message_info.connection_info.client_ip', 'ipAddress'),
      attachments: Number(pick(f, 'message_info.num_message_attachments') ?? 0) || 0,
      linkDomains: [...new Set(links)],
      isSpam: (pick(f, 'message_info.is_spam') ?? '').toLowerCase() === 'true',
      rules,
      quarantined: rules.some((r) => r.quarantine)
    };
  }
}
