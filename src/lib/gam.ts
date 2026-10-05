/**
 * GAM execution layer.
 *
 * Every rule in this file is a mistake made or narrowly avoided during the
 * 2026-09-08 → 09-23 campaigns. They are code, not documentation, because the
 * person on call at 22:00 will not have re-read the postmortem.
 *
 *  1. Gmail search CANNOT reliably match a bare domain inside a URL. A scan for
 *     `downloaddocc.com` returned ZERO hits for a domain provably present in message
 *     bodies. Scope on LURE TEXT; confirm payloads by fetching bodies.
 *  2. `includespamtrash` is NOT valid on `trash messages`. Use `in:anywhere`.
 *  3. Without `max_to_trash`, GAM silently under-deletes.
 *  4. Never sweep on `from:` alone. A sender-scoped sweep of a compromised partner
 *     account would have destroyed 51 live IEP / case-conference messages.
 *  5. Always verify after acting. A bulk sweep reported success while one copy
 *     survived unlabelled outside the Inbox.
 *  6. Never sweep internal senders or warning subjects — those are the responders,
 *     and their reports are the only record of who caught it.
 *  7. Trash, never delete.
 *
 * Destructive calls are gated on WARDEN_ALLOW_DESTRUCTIVE, mirroring Sentinel's
 * ALGO_ALLOW_REAL_DEVICES. A dev box must not be one typo away from a district-wide
 * mail deletion.
 */
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';

// Fixed by the installer's layout. The env override exists only for running tests and
// development off-host; it does not belong in a deployed .env.
export const LOG_DIR = process.env.WARDEN_LOG_DIR ?? '/var/lib/warden/joblogs';

export class UnsafeQueryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeQueryError';
  }
}

export class DestructiveDisabledError extends Error {
  constructor() {
    super(
      'Destructive operations are disabled. Set WARDEN_ALLOW_DESTRUCTIVE=1 on the ' +
        'production host to enable sweeps.'
    );
    this.name = 'DestructiveDisabledError';
  }
}

export interface GamSettings {
  gamPath: string;
  domains: Record<string, string>;
  maxToTrashPerMailbox: number;
  /** Label put on everything a sweep trashes. Blank disables. */
  sweepWarningLabel?: string;
  scanTimeoutSeconds: number;
  protectedSubjects: string[];
  protectInternalSenders: boolean;
}

/** Subjects that must never be swept: responder and warning traffic. */
export const DEFAULT_PROTECTED_SUBJECTS = [
  '[Phish Alert]',
  'DO NOT OPEN',
  'Phishing Alert',
  'Heads Up'
];

/**
 * Refuse a destructive query that is not narrowly scoped.
 *
 * A sweep must constrain on more than a sender. `from:` alone is how a partner
 * district's real casework gets deleted alongside the phish.
 */
export function assertSweepSafe(query: string, settings: GamSettings): void {
  const q = query.toLowerCase();
  const hasSender = q.includes('from:');

  /**
   * A Message-ID identifies ONE message — every copy of it is the same send. It is the
   * narrowest query Gmail has, so it is always safe to sweep on.
   *
   * It was missing from the narrowing list, so `rfc822msgid:<id> in:anywhere` — a single
   * BEC message in a single mailbox — fell through to "too broad" and could not be
   * removed. A guard that blocks the most precise query while allowing a quoted phrase is
   * backwards. (Protected subjects are still checked below, and the protective suffix is
   * still appended, so a Message-ID sweep still spares responder copies.)
   */
  const hasMessageId = /\brfc822msgid:\s*\S+/.test(q);

  const hasNarrowing =
    hasMessageId ||
    q.includes('subject:') ||
    query.includes('"') ||
    /downloaddoc|\.com\.br|lovable\.app/.test(q);

  if (hasSender && !hasNarrowing) {
    throw new UnsafeQueryError(
      'Sweep refused: this query scopes on sender only. Add a subject, a quoted lure ' +
        'phrase, or a payload host. On 2026-09-22 a sender-only sweep of ' +
        'a compromised partner-district account would have destroyed 51 active IEP messages.'
    );
  }
  if (!hasSender && !hasNarrowing) {
    throw new UnsafeQueryError(
      'Sweep refused: query is too broad to be destructive with. Narrow it with a ' +
        'Message-ID (rfc822msgid:…), a subject:, or a quoted lure phrase.'
    );
  }
  for (const subject of settings.protectedSubjects) {
    if (q.includes(subject.toLowerCase())) {
      throw new UnsafeQueryError(
        `Sweep refused: query targets the protected subject "${subject}". That is ` +
          'responder traffic — the record of who reported the attack.'
      );
    }
  }
}

/** Clauses appended to every sweep so responders are never caught in it. */
export function protectiveSuffix(settings: GamSettings): string {
  const parts: string[] = [];
  if (settings.protectInternalSenders) parts.push(`-from:${settings.domains.staff}`);
  for (const s of settings.protectedSubjects) parts.push(`-subject:"${s}"`);
  return parts.join(' ');
}

function entity(settings: GamSettings, domainKey: string): string[] {
  const domain = settings.domains[domainKey];
  if (!domain) throw new Error(`Unknown domain key: ${domainKey}`);
  return ['domains_ns', domain];
}

export interface RunResult {
  exitCode: number;
  logPath: string;
  timedOut: boolean;
  /** GAM walked every mailbox. See gamCompleted() — NOT the same as exitCode === 0. */
  completed: boolean;
}

/**
 * GAM7 exit 60 is NO_ENTITIES_FOUND: some mailbox matched nothing. On a domain-wide search
 * nearly every mailbox matches nothing, so a perfectly clean scope across 1,364 mailboxes
 * exits 60 essentially every time.
 *
 * Treating any non-zero exit as failure therefore marked every real scope INCOMPLETE and
 * kept the sweep gate permanently shut. Treating 60 as success unconditionally would be
 * the opposite mistake — it would accept a run that died partway through.
 *
 * So 60 is success only with evidence: the stderr log's last position line reads N/N,
 * meaning GAM reached the final mailbox. A timeout is never completion.
 */
export const GAM_NO_ENTITIES_FOUND = 60;

export function reachedEnd(stderr: string): boolean {
  let last: RegExpMatchArray | null = null;
  for (const m of stderr.matchAll(/\((\d+)\/(\d+)\)\s*$/gm)) last = m;
  return !!last && last[1] === last[2];
}

export function gamCompleted(exitCode: number, timedOut: boolean, stderr: string): boolean {
  if (timedOut) return false;
  if (exitCode === 0) return true;
  return exitCode === GAM_NO_ENTITIES_FOUND && reachedEnd(stderr);
}

async function run(
  settings: GamSettings,
  args: string[],
  jobId: string,
  ext: string
): Promise<RunResult> {
  await mkdir(LOG_DIR, { recursive: true });
  const logPath = path.join(LOG_DIR, `${jobId}.${ext}`);
  const errPath = path.join(LOG_DIR, `${jobId}.log`);

  return new Promise((resolve, reject) => {
    const out = createWriteStream(logPath);
    const err = createWriteStream(errPath);
    const child = spawn(settings.gamPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.pipe(out);
    child.stderr.pipe(err);

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, settings.scanTimeoutSeconds * 1000);

    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', async (code) => {
      clearTimeout(timer);
      const exitCode = code ?? -1;
      // Wait for the stderr stream to flush before reading it for the end-of-run check.
      await new Promise<void>((r) => (err.writableFinished ? r() : err.on('finish', () => r())));
      const stderr = await readFile(errPath, 'utf8').catch(() => '');
      resolve({ exitCode, logPath, timedOut, completed: gamCompleted(exitCode, timedOut, stderr) });
    });
  });
}

/** Read-only enumeration. Safe to run at any time. */
export function scopeArgs(settings: GamSettings, domainKey: string, query: string): string[] {
  return [
    ...entity(settings, domainKey),
    'print',
    'messages',
    'query',
    query,
    'headers',
    'From,To,Subject,Date',
    'showlabels'
  ];
}

export function runScope(
  settings: GamSettings,
  domainKey: string,
  query: string,
  jobId: string
): Promise<RunResult> {
  return run(settings, scopeArgs(settings, domainKey, query), jobId, 'csv');
}

/**
 * Destructive. Trash (never delete) messages matching a narrowly-scoped query.
 * Caller MUST have shown a preview and captured confirmation first.
 */
export function runSweep(
  settings: GamSettings,
  domainKey: string,
  query: string,
  jobId: string
): Promise<RunResult> {
  if (process.env.WARDEN_ALLOW_DESTRUCTIVE !== '1') throw new DestructiveDisabledError();
  assertSweepSafe(query, settings);

  const full = `${query} ${protectiveSuffix(settings)}`.trim();
  const args = [
    ...entity(settings, domainKey),
    'trash', // never `delete`
    'messages',
    'query',
    full,
    'doit',
    'max_to_trash', // omitting this silently under-deletes
    String(settings.maxToTrashPerMailbox)
  ];
  return run(settings, args, jobId, 'out');
}

/**
 * Post-sweep confirmation. `-in:trash` — anything returned here survived the sweep.
 *
 * TWO THINGS THIS MUST GET RIGHT, both of which it previously got wrong.
 *
 * 1. It must apply the SAME protective suffix the sweep did. The sweep deliberately spares
 *    internal senders and the protected subjects — `[Phish Alert]`, `DO NOT OPEN` and the
 *    rest — because those messages are the record of who caught the attack. Verifying
 *    without the suffix searches a wider set than was swept, so every responder copy the
 *    sweep was designed to keep comes back as a "survivor" and fires a verifyAlert email.
 *    A verify that cries wolf every time staff used the Phish Alert Button is a verify
 *    nobody reads by week two, which is the same end state as a verify that always says
 *    clean.
 *
 * 2. It must search `in:anywhere`. The surviving copy in the founding incident was
 *    unlabelled and OUTSIDE the Inbox — precisely what a default-scope query cannot see.
 *    The operator's scope query is inherited here, so if theirs lacked `in:anywhere` the
 *    verify would look in exactly the wrong place. It is forced, not assumed.
 *
 * `in:anywhere` includes Trash and Spam; `-in:trash` then subtracts Trash. The combination
 * is "everywhere except the place we just put it", which is the actual question.
 */
export function verifyQuery(settings: GamSettings, query: string): string {
  let q = `${query} ${protectiveSuffix(settings)} -in:trash`.replace(/\s+/g, ' ').trim();
  if (!/\bin:anywhere\b/i.test(q)) q = `${q} in:anywhere`;
  return q;
}

export function runVerify(
  settings: GamSettings,
  domainKey: string,
  query: string,
  jobId: string
): Promise<RunResult> {
  const q = verifyQuery(settings, query);
  return run(
    settings,
    [
      ...entity(settings, domainKey),
      'print',
      'messages',
      'query',
      q,
      'headers',
      'From,Subject',
      'showlabels'
    ],
    jobId,
    'csv'
  );
}

/** Parse the counts GAM prints during a sweep. */
export function parseSweepResult(stdout: string): { trashed: number; mailboxes: number } {
  let trashed = 0;
  for (const m of stdout.matchAll(/Trash (\d+) Message/g)) trashed += Number(m[1]);
  const mailboxes = stdout
    .split('\n')
    .filter((l) => l.startsWith('User:') && !l.includes('No Messages matched')).length;
  return { trashed, mailboxes };
}

/** Per-user persistence indicators — the check that found both real takeovers. */
export const ACCOUNT_CHECKS = [
  { name: 'filters', args: (u: string) => ['user', u, 'show', 'filters'] },
  { name: 'forward', args: (u: string) => ['user', u, 'show', 'forward'] },
  { name: 'forwardingaddresses', args: (u: string) => ['user', u, 'show', 'forwardingaddresses'] },
  { name: 'delegates', args: (u: string) => ['user', u, 'show', 'delegates'] },
  { name: 'asps', args: (u: string) => ['user', u, 'show', 'asps'] },
  { name: 'tokens', args: (u: string) => ['user', u, 'show', 'tokens'] }
] as const;

export function flagsFromAccountCheck(text: string): string[] {
  const flags: string[] = [];
  if (/Show [1-9]\d* Filters/.test(text)) flags.push('HAS FILTERS');
  if (text.includes('Forward Enabled: True')) flags.push('FORWARDING ON');
  if (/Show [1-9]\d* Forwarding Addresses/.test(text)) flags.push('FORWARD ADDRESSES');
  if (/Show [1-9]\d* Delegates/.test(text)) flags.push('DELEGATES');
  if (/Show [1-9]\d* Application Specific/.test(text)) flags.push('APP PASSWORDS');

  /**
   * OAuth grants. `show tokens` has been run since this check was written and its output
   * was never looked at, while the Accounts page advertised "OAuth scopes" as something
   * this covers.
   *
   * Do NOT flag merely having tokens. "Allowing an app access to Google data" is routine
   * ed-tech consent — 30 of 31 risky-action events in September — and a check that fires
   * on every Chromebook app is a check that gets ignored.
   *
   * What matters is a grant that can READ MAIL or CHANGE MAIL SETTINGS. That is
   * persistence which survives a password reset, which is the entire question this job is
   * asking. Reported as "review", not as a finding: a legitimate mail client looks the
   * same from here, and a human has to name the app.
   */
  const mailScopes = text.match(
    /https:\/\/(?:mail\.google\.com\/?|www\.googleapis\.com\/auth\/gmail\.(?:modify|settings\.basic|settings\.sharing|compose|send))/g
  );
  if (mailScopes?.length) {
    flags.push(`OAUTH MAIL SCOPES (${new Set(mailScopes).size} distinct — review the apps)`);
  }
  return flags;
}

/** Mailboxes the sweep actually trashed something in, read from GAM's own output. */
export function sweptMailboxes(stdout: string): string[] {
  const out = new Set<string>();
  for (const l of stdout.split('\n')) {
    if (!l.startsWith('User:') || l.includes('No Messages matched')) continue;
    const m = l.match(/^User:\s*([^\s,]+@[^\s,]+)/);
    if (m) out.add(m[1].toLowerCase());
  }
  return [...out];
}

/**
 * Put a visible warning label on what a sweep just trashed.
 *
 * Gmail messages are immutable — no API, GAM included, can change a delivered message's
 * subject or body. Rewriting would mean inserting an altered copy and PERMANENTLY deleting
 * the original, which destroys the evidence and breaks "trash, never delete". A label is
 * the one thing that can be changed: it shows as a red chip beside the subject in Trash
 * and in search, for the one person who goes digging.
 *
 * Touches only the mailboxes the sweep actually hit — never creates the label across the
 * whole domain. Best-effort by design: a labelling failure is reported, never allowed to
 * fail the sweep, which has already done the part that matters.
 *
 * Syntax verified against GAM7 on 2026-10-01: create label exits 50 on a duplicate
 * (harmless), modify exits 60 when nothing matched (harmless), colours go through
 * `update labelsettings`.
 */
export async function labelSwept(
  settings: GamSettings & { sweepWarningLabel?: string },
  mailboxes: string[],
  query: string
): Promise<{ ok: boolean; labelled: number; detail: string }> {
  const label = (settings.sweepWarningLabel ?? '').trim();
  if (!label || !mailboxes.length) return { ok: true, labelled: 0, detail: 'skipped' };

  const gam = (args: string[]) =>
    new Promise<{ out: string; code: number }>((resolve) => {
      let o = '';
      const c = spawn(settings.gamPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      c.stdout.on('data', (d) => (o += d));
      c.stderr.on('data', (d) => (o += d)); // drained, never left as an unread pipe
      const t = setTimeout(() => c.kill('SIGKILL'), settings.scanTimeoutSeconds * 1000);
      c.on('error', () => { clearTimeout(t); resolve({ out: o, code: -1 }); });
      c.on('close', (code) => { clearTimeout(t); resolve({ out: o, code: code ?? -1 }); });
    });

  // The same set the sweep acted on, restricted to Trash.
  const q = `${query} ${protectiveSuffix(settings)} in:trash`.replace(/\s+/g, ' ').trim();
  let labelled = 0;
  let failed = 0;

  for (let i = 0; i < mailboxes.length; i += 200) {
    const who = mailboxes.slice(i, i + 200).join(',');
    await gam(['users', who, 'create', 'label', label]); // 50 = already exists
    await gam(['users', who, 'update', 'labelsettings', label, 'backgroundcolor', '#cc3a21', 'textcolor', '#ffffff']);
    const r = await gam([
      'users', who, 'modify', 'messages', 'query', q,
      'addlabel', label, 'doit', 'max_to_modify', String(settings.maxToTrashPerMailbox)
    ]);
    if (r.code !== 0 && r.code !== 60) failed++;
    for (const m of r.out.matchAll(/Messages:\s*(\d+),\s*Modified/gi)) labelled += Number(m[1]);
    labelled += (r.out.match(/Message:\s*\S+,\s*Modified/gi) ?? []).length;
  }

  return {
    ok: failed === 0,
    labelled,
    detail: failed ? `labelling FAILED for ${failed} batch(es)` : `labelled "${label}" in ${mailboxes.length} mailbox(es)`
  };
}

/**
 * Trash a SPECIFIC set of messages in one mailbox by their Gmail message ids.
 *
 * This is the hand-picked counterpart to a query sweep: the operator ticked exact messages
 * from a scope result, so there is no query to over-reach and no `assertSweepSafe` to run —
 * explicit ids in a named mailbox are the narrowest target Gmail has, narrower even than
 * `rfc822msgid:`. Still trash, never delete. Returns null for a bad mailbox or when no id
 * survives validation, so the runner never hands GAM a half-formed command.
 *
 * Gmail message ids are the immutable API ids GAM prints in the `id` column of
 * `print messages` — hex-ish `[A-Za-z0-9_-]+`. Anything else is rejected rather than passed.
 */
function cleanIds(ids: string[]): string[] {
  return ids.map((x) => String(x ?? '').trim()).filter((x) => /^[A-Za-z0-9_-]+$/.test(x));
}
const MAILBOX_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function trashIdsArgs(mailbox: string, ids: string[]): string[] | null {
  const m = String(mailbox ?? '').trim().toLowerCase();
  const clean = cleanIds(ids);
  if (!MAILBOX_RE.test(m) || !clean.length) return null;
  return ['user', m, 'trash', 'messages', 'ids', clean.join(','), 'doit'];
}

export function labelIdsArgs(mailbox: string, ids: string[], label: string): string[] | null {
  const m = String(mailbox ?? '').trim().toLowerCase();
  const clean = cleanIds(ids);
  if (!MAILBOX_RE.test(m) || !clean.length || !label.trim()) return null;
  return ['user', m, 'modify', 'messages', 'ids', clean.join(','), 'addlabel', label, 'doit'];
}

export interface TrashItem { mailbox: string; id: string; }

/**
 * Group hand-picked (mailbox, id) pairs by mailbox and, for each, apply the warning label
 * then trash the named messages. Gated by WARDEN_ALLOW_DESTRUCTIVE exactly like `runSweep`.
 * GAM's exit code is the success signal (0 = done, 60 = nothing matched / already gone —
 * both benign), consistent with how the rest of this module treats GAM: a mailbox whose
 * trash command did not exit cleanly is reported as a failure, never silently counted as done.
 */
export async function runTrashSelected(
  settings: GamSettings & { sweepWarningLabel?: string },
  items: TrashItem[]
): Promise<{ requested: number; trashed: number; mailboxes: number; failures: string[] }> {
  if (process.env.WARDEN_ALLOW_DESTRUCTIVE !== '1') throw new DestructiveDisabledError();

  const byBox = new Map<string, string[]>();
  for (const it of items) {
    const mb = String(it?.mailbox ?? '').trim().toLowerCase();
    const [id] = cleanIds([it?.id ?? '']);
    if (!MAILBOX_RE.test(mb) || !id) continue;
    const list = byBox.get(mb) ?? [];
    list.push(id);
    byBox.set(mb, list);
  }

  const label = (settings.sweepWarningLabel ?? '').trim();
  const gam = (args: string[]) =>
    new Promise<{ out: string; code: number }>((resolve) => {
      let o = '';
      const c = spawn(settings.gamPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      c.stdout.on('data', (d) => (o += d));
      c.stderr.on('data', (d) => (o += d)); // drained, never left as an unread pipe
      const t = setTimeout(() => c.kill('SIGKILL'), settings.scanTimeoutSeconds * 1000);
      c.on('error', () => { clearTimeout(t); resolve({ out: o, code: -1 }); });
      c.on('close', (code) => { clearTimeout(t); resolve({ out: o, code: code ?? -1 }); });
    });

  let requested = 0;
  let trashed = 0;
  const failures: string[] = [];

  for (const [mb, ids] of byBox) {
    requested += ids.length;
    // Label first so the warning chip is on the message, then trash. Labelling is best-effort
    // — a label failure must not stop the message being removed.
    if (label) {
      await gam(['user', mb, 'create', 'label', label]); // exit 50 = already exists, harmless
      await gam(['user', mb, 'update', 'labelsettings', label, 'backgroundcolor', '#cc3a21', 'textcolor', '#ffffff']);
      const la = labelIdsArgs(mb, ids, label);
      if (la) await gam(la);
    }
    const ta = trashIdsArgs(mb, ids);
    if (!ta) { failures.push(`${mb}: no valid ids`); continue; }
    const r = await gam(ta);
    // Only a clean exit 0 means every named message was trashed. GAM returns 50 when any id
    // did not exist (e.g. already gone) — a partial that must be surfaced, never counted as
    // done, so silence here always means "removed", not "could not".
    if (r.code === 0) trashed += ids.length;
    else failures.push(`${mb}: GAM exit ${r.code}${/Does not exist/i.test(r.out) ? ' (a message no longer existed)' : ''}`);
  }

  return { requested, trashed, mailboxes: byBox.size, failures };
}

/**
 * Parse the account-check blob into a per-mechanism breakdown with an overall verdict, so
 * the job page can say plainly "clean" vs "review these", with the detail behind each line
 * — not just a terse flag string. The blob is the concatenated output of ACCOUNT_CHECKS,
 * each block headed `===== <name> (exit N[, TIMED OUT]) =====`.
 *
 * Verdict is deliberately conservative: anything that can persist past a password reset
 * (a filter, forwarding, a delegate, an app password, or an OAuth app that can read or
 * change mail) is surfaced for REVIEW with a human to name it, because a legitimate mail
 * client and an attacker's grant look identical from here. A check that did not complete
 * makes the whole result INCONCLUSIVE — silence must never read as clean.
 */
export interface OAuthApp {
  clientId: string;
  name: string;
  scopes: string[];
  mailAccess: boolean;
}
export interface AccountMechanism {
  name: string;
  status: 'clean' | 'review' | 'failed';
  summary: string;
  detail: string[];
}
export interface AccountCheckReport {
  verdict: 'clean' | 'review' | 'inconclusive';
  mechanisms: AccountMechanism[];
  apps: OAuthApp[];
}

const MAIL_SCOPE =
  /^https:\/\/(?:mail\.google\.com\/?|www\.googleapis\.com\/auth\/gmail\.(?:modify|settings\.basic|settings\.sharing|compose|send|insert|labels))/;

function blockOf(blob: string, name: string): { body: string; exit: number; timedOut: boolean } | null {
  // Line-based rather than one big RegExp: the headers are `===== <name> (exit N[, TIMED OUT]) =====`.
  const lines = blob.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const h = lines[i].match(/^=====\s*(\S+)\s*\(exit (-?\d+)(, TIMED OUT)?\)\s*=====\s*$/);
    if (!h || h[1] !== name) continue;
    const body: string[] = [];
    for (let j = i + 1; j < lines.length && !/^=====/.test(lines[j]); j++) body.push(lines[j]);
    return { exit: Number(h[2]), timedOut: Boolean(h[3]), body: body.join('\n') };
  }
  return null;
}

function countShow(body: string): number {
  return Number(body.match(/Show (\d+)\b/)?.[1] ?? '0');
}

export function parseOAuthApps(body: string): OAuthApp[] {
  const apps: OAuthApp[] = [];
  const parts = body.split(/^\s*Client ID:\s*/m).slice(1);
  for (const p of parts) {
    const clientId = p.split(/\s/)[0] ?? '';
    const name = p.match(/displayText:\s*(.+)/)?.[1]?.trim() || '(unnamed app)';
    const scopes: string[] = [];
    const sIdx = p.indexOf('scopes:');
    if (sIdx >= 0) {
      for (const line of p.slice(sIdx + 7).split('\n')) {
        const t = line.trim();
        if (!t) continue;
        // Stop at the next field (e.g. "anonymous:") — but a scope URL like "https://…" is
        // NOT a field, so only break on "word:" that is not followed by "//".
        if (/^[a-zA-Z][a-zA-Z]+:(?!\/\/)/.test(t)) break;
        scopes.push(t);
      }
    }
    apps.push({ clientId, name, scopes, mailAccess: scopes.some((x) => MAIL_SCOPE.test(x)) });
  }
  return apps;
}

export function parseAccountCheck(blob: string): AccountCheckReport {
  const mechanisms: AccountMechanism[] = [];
  const mech = (name: string, blockName: string, present: (b: string) => { review: boolean; summary: string; detail: string[] }) => {
    const b = blockOf(blob, blockName);
    if (!b || b.timedOut || (b.exit !== 0 && b.exit !== 60)) {
      mechanisms.push({ name, status: 'failed', summary: b?.timedOut ? 'did not complete (timed out)' : 'did not complete', detail: [] });
      return;
    }
    const r = present(b.body);
    mechanisms.push({ name, status: r.review ? 'review' : 'clean', summary: r.summary, detail: r.detail });
  };

  mech('Filters', 'filters', (b) => {
    const n = countShow(b);
    // When filters exist, GAM prints each below the header; keep those lines as detail.
    const detail = n > 0 ? b.split('\n').map((l) => l.trim()).filter((l) => l && !/^User:/.test(l)) : [];
    return { review: n > 0, summary: n === 0 ? 'none' : `${n} filter${n === 1 ? '' : 's'} — review what they do`, detail };
  });
  mech('Forwarding', 'forward', (b) => {
    const on = /Forward Enabled:\s*True/i.test(b);
    const to = b.match(/Forwarding Address:\s*(\S+)/i)?.[1];
    return { review: on, summary: on ? `ON${to ? ` → ${to}` : ''}` : 'off', detail: [] };
  });
  mech('Forwarding addresses', 'forwardingaddresses', (b) => {
    const n = countShow(b);
    const detail = b.split('\n').map((l) => l.trim()).filter((l) => l && !/^User:/.test(l));
    return { review: n > 0, summary: n === 0 ? 'none' : `${n}`, detail };
  });
  mech('Delegates', 'delegates', (b) => {
    const n = countShow(b);
    const detail = b.split('\n').map((l) => l.trim()).filter((l) => l && !/^User:/.test(l));
    return { review: n > 0, summary: n === 0 ? 'none' : `${n} — someone else can open this mailbox`, detail };
  });
  mech('App passwords', 'asps', (b) => {
    const n = countShow(b);
    return { review: n > 0, summary: n === 0 ? 'none' : `${n}`, detail: [] };
  });

  // OAuth apps: listed in full, those with mail access flagged for review.
  const tb = blockOf(blob, 'tokens');
  let apps: OAuthApp[] = [];
  if (!tb || tb.timedOut || (tb.exit !== 0 && tb.exit !== 60)) {
    mechanisms.push({ name: 'Connected apps (OAuth)', status: 'failed', summary: 'did not complete', detail: [] });
  } else {
    apps = parseOAuthApps(tb.body);
    const mail = apps.filter((a) => a.mailAccess);
    mechanisms.push({
      name: 'Connected apps (OAuth)',
      status: mail.length ? 'review' : 'clean',
      summary: mail.length
        ? `${mail.length} of ${apps.length} app${apps.length === 1 ? '' : 's'} can read or change mail — confirm you recognise them`
        : `${apps.length} app${apps.length === 1 ? '' : 's'}, none with mail access`,
      detail: mail.map((a) => `${a.name} — ${a.scopes.filter((s) => MAIL_SCOPE.test(s)).join(', ')}`)
    });
  }

  const verdict: AccountCheckReport['verdict'] = mechanisms.some((m) => m.status === 'failed')
    ? 'inconclusive'
    : mechanisms.some((m) => m.status === 'review')
      ? 'review'
      : 'clean';
  return { verdict, mechanisms, apps };
}
