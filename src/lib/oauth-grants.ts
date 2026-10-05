/**
 * OAuth-grant monitor (pure logic).
 *
 * The Erin incident made the lesson concrete: a mail-focused sweep reads CLEAN over a token
 * takeover, because the persistence is the OAuth grant, not anything in the mailbox. A
 * password reset does not revoke it. This watches the Admin token audit log for NEW
 * authorizations that can read or change mail and surfaces any to an app that is not a
 * recognised mail client — the modern replacement for the forwarding-filter persistence the
 * account check already covers.
 *
 * Security posture is default-deny BY CLIENT ID. An OAuth app can name itself anything,
 * including "Microsoft Outlook", so a name allow-list is a convenience, never the control;
 * the trustworthy allow-list is the cryptographic client_id. The operator allow-lists the
 * legitimate mail clients their staff actually use once (the first scan surfaces them), and
 * after that a new mail-capable grant to an unknown client_id is the signal.
 *
 * Pure: no GAM, no DB. The scan script does the I/O and passes the fetched CSV in.
 */
import { MAIL_SCOPE } from './gam';
import { parseCsvLine } from './loginscan';

export interface GrantEvent {
  mailbox: string;
  ts: Date;
  appName: string;
  clientId: string;
  clientType: string;
  scopes: string[];
  ip: string | null;
}

/**
 * Parse `gam report token ... event authorize` CSV into authorize events, keeping only the
 * configured domains. Columns are located BY NAME — the token report's layout has drifted
 * before — and an empty or header-only CSV yields `[]`, which the caller must treat as "saw
 * nothing", never "nothing to find" (the empty-vs-failed trap): the scan script throws on a
 * non-zero GAM exit so a failed fetch cannot masquerade as a clean window.
 */
export function parseGrantEvents(csv: string, domains: string[]): GrantEvent[] {
  const lines = csv.split('\n').filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = parseCsvLine(lines[0]);
  const ix = (n: string) => header.indexOf(n);
  const iName = ix('name');
  const iEmail = ix('actor.email');
  const iApp = ix('app_name');
  const iClient = ix('client_id');
  const iType = ix('client_type');
  const iTime = ix('id.time');
  const iIp = ix('ipAddress');
  const iScope = ix('scope');
  if (iName < 0 || iEmail < 0 || iScope < 0 || iClient < 0) return [];
  const suffixes = domains.filter(Boolean).map((d) => `@${d.toLowerCase()}`);
  const out: GrantEvent[] = [];
  for (const line of lines.slice(1)) {
    const f = parseCsvLine(line);
    if ((f[iName] ?? '') !== 'authorize') continue;
    const mailbox = (f[iEmail] ?? '').toLowerCase();
    if (suffixes.length && !suffixes.some((s) => mailbox.endsWith(s))) continue;
    const t = iTime >= 0 ? new Date(f[iTime]) : new Date(NaN);
    if (Number.isNaN(t.getTime())) continue;
    out.push({
      mailbox,
      ts: t,
      appName: f[iApp] || '(unnamed app)',
      clientId: f[iClient] || '',
      clientType: iType >= 0 ? f[iType] || '' : '',
      scopes: (f[iScope] || '').split(/\s+/).filter(Boolean),
      ip: iIp >= 0 ? f[iIp] || null : null
    });
  }
  return out;
}

export interface GrantAllow {
  /** Exact client_id allow-list — the trustworthy control. */
  clientIds: Set<string>;
  /** Case-insensitive app-name substrings — a convenience, and spoofable; never the control. */
  namePatterns: string[];
}

export function mailScopesOf(scopes: string[]): string[] {
  return scopes.filter((s) => MAIL_SCOPE.test(s));
}

export function isAllowed(e: GrantEvent, allow: GrantAllow): boolean {
  if (e.clientId && allow.clientIds.has(e.clientId)) return true;
  const n = e.appName.toLowerCase();
  return allow.namePatterns.some((p) => p && n.includes(p.toLowerCase()));
}

export interface GrantFlag {
  mailbox: string;
  ts: Date;
  appName: string;
  clientId: string;
  clientType: string;
  /** The mail-capable scopes only, for the reason text. */
  scopes: string[];
  ip: string | null;
  /** How many DISTINCT mailboxes granted this same app in the window. */
  fanOut: number;
  reasons: string[];
}

/**
 * From a window of authorize events, pick the NEW mail-capable grants worth a human: a mail
 * scope AND not allow-listed. Deduplicated to one per (mailbox, client_id) keeping the
 * latest — an app that re-authorizes several times in a window is one fact, the same "one
 * fact, not many" rule the sign-in scan uses.
 *
 * Each flag carries `fanOut`: how many distinct mailboxes granted this same app in the
 * window. An app on many mailboxes is an enterprise rollout (Outlook, an SSO suite, the
 * district's own GAM service) and is surfaced so it can be allow-listed in one pass; an app
 * on a single mailbox is the shape of a targeted token takeover. Sorted single-mailbox
 * grants first, so the targeted ones are read before the bulk rollout noise.
 */
export function selectGrantFlags(events: GrantEvent[], allow: GrantAllow): GrantFlag[] {
  const mail = events.filter(
    (e) => e.scopes.some((s) => MAIL_SCOPE.test(s)) && !isAllowed(e, allow)
  );

  const fan = new Map<string, Set<string>>();
  for (const e of mail) {
    const s = fan.get(e.clientId) ?? new Set<string>();
    s.add(e.mailbox);
    fan.set(e.clientId, s);
  }

  const byKey = new Map<string, GrantEvent>();
  for (const e of mail) {
    const k = `${e.mailbox}\u0000${e.clientId}`;
    const prev = byKey.get(k);
    if (!prev || e.ts > prev.ts) byKey.set(k, e);
  }

  const out: GrantFlag[] = [];
  for (const e of byKey.values()) {
    const fanOut = fan.get(e.clientId)?.size ?? 1;
    const scopes = mailScopesOf(e.scopes);
    out.push({
      mailbox: e.mailbox,
      ts: e.ts,
      appName: e.appName,
      clientId: e.clientId,
      clientType: e.clientType,
      scopes,
      ip: e.ip,
      fanOut,
      reasons: [
        `"${e.appName}" was granted access that can read or change this mailbox's mail`,
        `Scopes: ${scopes.join(', ')}`,
        fanOut > 1
          ? `Same app authorized on ${fanOut} mailboxes in this window — likely an enterprise or ed-tech rollout, not a targeted takeover; allow-list it by client ID once recognised`
          : 'Authorized on this mailbox only — the shape of a targeted token takeover; confirm the user recognises the app'
      ]
    });
  }
  return out.sort((a, b) => a.fanOut - b.fanOut || b.ts.getTime() - a.ts.getTime());
}
