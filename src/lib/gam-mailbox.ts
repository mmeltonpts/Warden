/**
 * Single-mailbox GAM reads for the sign-in verification: find the email Warden sent and read
 * its labels, read replies out of the reply mailbox, and list an account's filters.
 *
 * Separate from gam.ts because these are fast, one-mailbox, buffered reads — not the
 * domain-wide streamed scans. execFile buffers both stdout and stderr, so neither pipe can
 * fill and block GAM (the deadlock CLAUDE.md warns about applies to the streamed path).
 */
import { execFile } from 'node:child_process';
import { csvRecords } from './gmaillog';

function run(gamPath: string, args: string[], timeoutMs = 60_000): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve) => {
    execFile(gamPath, args, { timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 }, (err, stdout) => {
      const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? Number((err as { code?: number }).code) : -1) : 0;
      resolve({ code, stdout: stdout ?? '' });
    });
  });
}

function rows(csv: string): Array<Record<string, string>> {
  const recs = csvRecords(csv);
  if (recs.length < 2) return [];
  const header = recs[0];
  return recs.slice(1).map((r) => {
    const o: Record<string, string> = {};
    header.forEach((h, i) => (o[h] = r[i] ?? ''));
    return o;
  });
}

/**
 * The labels on a message Warden sent, found by its Message-ID. Returns null when no such
 * message exists in the mailbox at all (deleted outright) — which hiddenVerdict() reads as
 * hidden. GAM exit 60 means "no entity matched", i.e. not found.
 */
export async function messageLabels(
  gamPath: string,
  mailbox: string,
  rfcMessageId: string
): Promise<string[] | null> {
  const id = rfcMessageId.replace(/[<>]/g, '');
  const { code, stdout } = await run(gamPath, [
    'user', mailbox, 'print', 'messages',
    'query', `rfc822msgid:${id} in:anywhere`,
    'showlabels'
  ]);
  const r = rows(stdout);
  if (!r.length) return code === 60 ? null : null;
  // The Labels column is a space- or comma-separated list of label IDs/names.
  const labels = r[0]['Labels'] ?? r[0]['labels'] ?? '';
  return labels.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
}

/**
 * Replies in the reply mailbox that carry a given code in their subject, newest first. Reads
 * the From/Subject/Date and the body text so parseReplyDecision can read the answer.
 */
export async function findReplies(
  gamPath: string,
  replyMailbox: string,
  code: string,
  lookbackDays = 4
): Promise<Array<{ from: string; subject: string; date: string; body: string }>> {
  const { stdout } = await run(gamPath, [
    'user', replyMailbox, 'print', 'messages',
    'query', `"${code}" newer_than:${lookbackDays}d in:anywhere`,
    'headers', 'From,Subject,Date',
    'showbody'
  ]);
  return rows(stdout).map((r) => ({
    from: r['From'] ?? '',
    subject: r['Subject'] ?? '',
    date: r['Date'] ?? '',
    body: r['Body'] ?? r['body'] ?? ''
  }));
}

/**
 * Mail filters on an account whose action hides mail (delete, archive, mark read, move to a
 * label) AND whose criteria mention a security keyword. That specific shape — "anything
 * saying 'password' or 'suspicious', make it disappear" — is an attacker covering their
 * tracks, and it is worth flagging on its own during a verification.
 */
export async function suspiciousFilters(gamPath: string, mailbox: string): Promise<string[]> {
  const { stdout } = await run(gamPath, ['user', mailbox, 'print', 'filters']);
  const hits: string[] = [];
  const KEYWORDS = /password|security|suspicious|sign[\s-]?in|hack|phish|alert|verify|unauthor|compromis|login/i;
  const HIDES = /trash|delete|archive|shouldArchive|markread|markRead|markAsRead|label|forward/i;
  for (const f of rows(stdout)) {
    const criteria = [f['from'], f['to'], f['subject'], f['query'], f['hasTheWord'], f['haswords']].filter(Boolean).join(' ');
    const action = [f['shouldTrash'], f['shouldArchive'], f['shouldMarkAsRead'], f['label'], f['forward'], f['action']].filter((v) => v && v !== 'False').join(' ');
    const line = `${criteria} ${action}`;
    if (KEYWORDS.test(criteria) && HIDES.test(line)) {
      hits.push(`criteria "${criteria.slice(0, 80)}" → ${action.slice(0, 60)}`);
    }
  }
  return hits;
}
