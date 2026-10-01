/**
 * Turning a Falcon alert into something Warden can correlate.
 *
 * Shapes taken from real alerts on this tenant (GovCloud, 2026-10-01), not documentation:
 * `device.hostname`, `user_name`/`user_names`, `pattern_disposition_description`,
 * `parent_details.cmdline`, `grandparent_details.cmdline`. The ScreenConnect intrusion was
 * only visible as such in the GRANDPARENT command line — the alert itself was a blocked
 * PowerShell, the parent a .cmd in SystemTemp, and the grandparent the remote-access
 * client with its relay in the `h=` parameter. A parser that read `cmdline` alone would have
 * filed it as "someone ran a script".
 */

export interface FalconAlertRaw {
  composite_id: string;
  created_timestamp: string;
  updated_timestamp?: string;
  severity?: number;
  severity_name?: string;
  status?: string;
  product?: string;
  name?: string;
  display_name?: string;
  description?: string;
  tactic?: string;
  technique?: string;
  technique_id?: string;
  device?: { hostname?: string; device_id?: string; local_ip?: string };
  user_name?: string;
  user_names?: string[];
  pattern_disposition_description?: string;
  filename?: string;
  filepath?: string;
  cmdline?: string;
  parent_details?: { cmdline?: string; filename?: string };
  grandparent_details?: { cmdline?: string; filename?: string };
  sha256?: string;
  falcon_host_link?: string;
}

const SEVERITY_ORDER = ['informational', 'low', 'medium', 'high', 'critical'];

export function severityRank(name: string | null | undefined): number {
  const i = SEVERITY_ORDER.indexOf(String(name ?? '').toLowerCase());
  return i < 0 ? -1 : i;
}

/**
 * Map Falcon's user field to a mailbox.
 *
 * Seen in practice: "jane.doe@example.org", "jane.doe", "Margaret.Lastnam" (truncated at
 * 20 characters), and machine accounts "LAB-PC-0123$" for anything
 * running as SYSTEM — which is exactly how a remote-access service runs. Machine accounts
 * map to nothing rather than to a guess. Truncated names map to nothing too; a wrong
 * person attached to an intrusion is worse than none.
 */
export function mapMailbox(
  names: Array<string | null | undefined>,
  domains: { staff: string; students?: string },
  knownMailboxes?: Set<string>
): string | null {
  for (const raw of names) {
    const n = String(raw ?? '').trim().toLowerCase();
    if (!n || n.endsWith('$')) continue;
    const bare = n.includes('\\') ? n.split('\\').pop()! : n;
    if (bare.includes('@')) {
      if (bare.endsWith(`@${domains.staff}`) || (domains.students && bare.endsWith(`@${domains.students}`))) {
        return bare;
      }
      continue;
    }
    const guess = `${bare}@${domains.staff}`;
    if (!knownMailboxes || knownMailboxes.has(guess)) return guess;
  }
  return null;
}

/**
 * Hosts an attacker's tooling talks to, from the whole process tree.
 *
 * ScreenConnect carries its relay as `h=<host>`; downloaders carry URLs. Both are what
 * should be blocked at DNS and matched against indicators.
 */
export function extractHosts(...texts: Array<string | null | undefined>): string[] {
  const out = new Set<string>();
  const t = texts.filter(Boolean).join(' ');
  for (const m of t.matchAll(/[?&]h=([a-z0-9.-]+\.[a-z]{2,})/gi)) out.add(m[1].toLowerCase());
  for (const m of t.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) out.add(m[1].toLowerCase());
  for (const m of t.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)) {
    const ip = m[1];
    if (!/^(10|127|169\.254|192\.168)\./.test(ip) && !/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) out.add(ip);
  }
  return [...out].filter((h) => !/(^|\.)microsoft\.com$|(^|\.)windowsupdate\.com$/.test(h));
}

export interface EdrRow {
  compositeId: string;
  createdAt: Date;
  updatedAt: Date;
  severity: number;
  severityName: string;
  status: string;
  product: string | null;
  name: string | null;
  displayName: string | null;
  description: string | null;
  tactic: string | null;
  technique: string | null;
  techniqueId: string | null;
  hostname: string | null;
  deviceId: string | null;
  localIp: string | null;
  userName: string | null;
  mailbox: string | null;
  action: string | null;
  blocked: boolean;
  filename: string | null;
  cmdline: string | null;
  parentCmd: string | null;
  grandCmd: string | null;
  sha256: string | null;
  hosts: string;
  falconLink: string | null;
}

const cap = (s: string | null | undefined, n: number) => (s ? s.slice(0, n) : null);

export function toEdrRow(
  a: FalconAlertRaw,
  domains: { staff: string; students?: string },
  knownMailboxes?: Set<string>
): EdrRow {
  const action = a.pattern_disposition_description ?? null;
  return {
    compositeId: a.composite_id,
    createdAt: new Date(a.created_timestamp),
    updatedAt: new Date(a.updated_timestamp ?? a.created_timestamp),
    severity: a.severity ?? 0,
    severityName: a.severity_name ?? 'Unknown',
    status: a.status ?? 'new',
    product: a.product ?? null,
    name: a.name ?? null,
    displayName: a.display_name ?? a.name ?? null,
    description: cap(a.description, 2000),
    tactic: a.tactic ?? null,
    technique: a.technique ?? null,
    techniqueId: a.technique_id ?? null,
    hostname: a.device?.hostname ?? null,
    deviceId: a.device?.device_id ?? null,
    localIp: a.device?.local_ip ?? null,
    userName: a.user_name ?? null,
    mailbox: mapMailbox([...(a.user_names ?? []), a.user_name], domains, knownMailboxes),
    action,
    // "Prevention, operation blocked." / "process was blocked from execution". Anything
    // else — "Detection, standard detection." above all — means it RAN.
    blocked: /block|prevent|kill|quarantine/i.test(action ?? '') && !/^detection, standard/i.test(action ?? ''),
    filename: a.filename ?? null,
    cmdline: cap(a.cmdline, 4000),
    parentCmd: cap(a.parent_details?.cmdline, 4000),
    grandCmd: cap(a.grandparent_details?.cmdline, 4000),
    sha256: a.sha256 ?? null,
    hosts: JSON.stringify(extractHosts(a.cmdline, a.parent_details?.cmdline, a.grandparent_details?.cmdline)),
    falconLink: a.falcon_host_link ?? null
  };
}

export interface HostLogin {
  user: string;
  at: Date;
}

/**
 * Who was signed in to a host when an alert fired.
 *
 * Remote-access services run as SYSTEM, so every ScreenConnect detection carried a machine
 * account ("LAB-PC-0123$") and read "no user" — including the one on the PC of a staff
 * member who had been sent the fake DocuSign. Falcon's per-host login history names the
 * person: the most recent interactive sign-in AT OR BEFORE the alert. A later sign-in is
 * never used — the next person to sit at the machine did not cause what happened before
 * they arrived. Machine accounts (`WORKGROUP\HOST$`) are skipped.
 *
 * Bounded to 7 days back: an alert on a PC nobody has signed in to for a month belongs to
 * nobody in particular, and attaching the last occupant would be a guess.
 */
export function userAtAlert(
  logins: HostLogin[],
  alertAt: Date,
  domains: { staff: string; students?: string },
  knownMailboxes?: Set<string>,
  maxAgeMs = 7 * 86_400_000
): { mailbox: string; loginUser: string; loginAt: Date } | null {
  const before = logins
    .filter((l) => l.at.getTime() <= alertAt.getTime() && alertAt.getTime() - l.at.getTime() <= maxAgeMs)
    .sort((a, b) => b.at.getTime() - a.at.getTime());
  for (const l of before) {
    const mb = mapMailbox([l.user], domains, knownMailboxes);
    if (mb) return { mailbox: mb, loginUser: l.user, loginAt: l.at };
  }
  return null;
}

/**
 * Fallback when the alert predates the login history Falcon still holds (it keeps only a
 * host's most recent sign-ins, so a 9/28 alert may have nothing at or before it).
 *
 * If EVERY interactive sign-in Falcon has for the host is the same person, that person is
 * the PC's usual user — reported as such, never as "signed in at the time". If the history
 * shows two or more people, nobody is named: a shared PC's last occupant is a guess.
 */
export function usualUser(
  logins: HostLogin[],
  domains: { staff: string; students?: string },
  knownMailboxes?: Set<string>
): string | null {
  const people = new Set(
    logins.map((l) => mapMailbox([l.user], domains, knownMailboxes)).filter((m): m is string => !!m)
  );
  return people.size === 1 ? [...people][0] : null;
}
