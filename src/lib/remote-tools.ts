/**
 * Remote-access tool inventory: who has what, and whether it is allowed.
 *
 * Built after Falcon's application inventory showed eight staff running a ScreenConnect
 * installer within the same hour on 9/22 — six days before the first alert — and two PCs
 * carrying two separate attacker instances each. Remote-access tools are the attacker's
 * favourite foothold precisely because they are legitimate software: no detection fires for
 * "TeamViewer ran". The only control is knowing which tools are approved, for whom, and
 * flagging everything else.
 */

export interface ToolRow {
  tool: string;            // watch-list entry it matched
  appName: string;
  version: string | null;
  hostname: string;
  lastUser: string | null; // as Falcon reports it — may be a SID or a machine account
  lastUsedAt: string | null;
  fileName: string | null;
}

export type Verdict = 'banned' | 'approved' | 'unapproved';

export function splitList(s: string | null | undefined): string[] {
  return String(s ?? '')
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** First watch-list entry contained in the app name (case-insensitive), or null. */
export function matchTool(appName: string, watch: string[]): string | null {
  const n = appName.toLowerCase();
  return watch.find((w) => n.includes(w.toLowerCase())) ?? null;
}

/** A service account or SYSTEM SID: the tool runs unattended, always on. */
export function isServiceUser(u: string | null | undefined): boolean {
  const v = String(u ?? '');
  return v === 'S-1-5-18' || v === 'S-1-5-19' || v === 'S-1-5-20' || v.endsWith('$');
}

function bareUser(u: string | null | undefined): string {
  return String(u ?? '').toLowerCase().split('\\').pop()!.split('@')[0];
}

/**
 * Approved entries, comma or newline separated:
 *   "Splashtop"              approved for anyone, anywhere
 *   "PuTTY@jane.tech"        approved only when that person is the user
 *   "Parsec@LAB-PC-01"       approved only on that PC
 * A banned tool is banned whatever the approved list says — approval cannot override a ban,
 * because "someone added it to the allow list" is exactly how a ban quietly stops working.
 */
export function classify(row: ToolRow, banned: string[], approved: string[]): Verdict {
  const name = row.appName.toLowerCase();
  if (banned.some((b) => name.includes(b.toLowerCase()))) return 'banned';
  for (const entry of approved) {
    const [tool, scope] = entry.split('@').map((x) => x.trim());
    if (!tool || !name.includes(tool.toLowerCase())) continue;
    if (!scope) return 'approved';
    const sc = scope.toLowerCase();
    if (row.hostname.toLowerCase() === sc) return 'approved';
    if (bareUser(row.lastUser) === sc.split('@')[0]) return 'approved';
  }
  return 'unapproved';
}

export const DEFAULT_WATCH = [
  'ScreenConnect', 'ConnectWise', 'AnyDesk', 'TeamViewer', 'Splashtop', 'Parsec', 'RustDesk',
  'PuTTY', 'mRemoteNG', 'Royal TS', 'FreeRDP', 'Atera', 'MeshCentral', 'LogMeIn', 'GoTo',
  'Remote Utilities', 'Supremo', 'Zoho Assist', 'SimpleHelp', 'Kaseya', 'NinjaRMM', 'N-able',
  'Action1', 'Chrome Remote Desktop', 'ngrok', 'Code Tunnel', 'DWService', 'Radmin',
  'UltraViewer', 'TightVNC', 'RealVNC', 'UltraVNC'
].join(', ');
