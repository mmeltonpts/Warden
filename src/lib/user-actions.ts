/**
 * Runs the account response actions through GAM. Single-user, quick, buffered reads — the
 * same execFile pattern as gam-mailbox.ts, so neither pipe can fill and block GAM.
 *
 * Server-only. Every caller must already have checked the operator's role and the typed
 * confirmation; this layer just executes and reports, and never decides whether it should.
 */
import { execFile } from 'node:child_process';
import { errText } from './errors';
import { gamArgsForAction, gamArgsForRemove, passwordFromOutput, type ResponseAction, type RemoveKind } from './response-actions';

function run(gamPath: string, args: string[], timeoutMs = 60_000): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(gamPath, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const out = `${stdout ?? ''}${stderr ?? ''}`.trim();
      if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') { resolve({ code: 127, out: `cannot execute ${gamPath}` }); return; }
      const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? Number((err as { code?: number }).code) : -1) : 0;
      resolve({ code, out: out || (err ? errText(err) : '') });
    });
  });
}

export interface ActionResult {
  ok: boolean;
  detail: string;
  /** Only for a password reset, and only on success. Shown once, never stored. */
  password?: string;
}

export async function runUserAction(gamPath: string, mailbox: string, action: ResponseAction): Promise<ActionResult> {
  const args = gamArgsForAction(action, mailbox);
  if (!args) return { ok: false, detail: 'invalid action or mailbox' };
  const r = await run(gamPath, args);
  if (r.code !== 0) {
    return { ok: false, detail: r.out.split('\n').slice(0, 3).join(' ').slice(0, 300) || `gam exit ${r.code}` };
  }
  if (action === 'reset') {
    const pw = passwordFromOutput(r.out);
    return { ok: true, detail: 'new password generated; change forced at next sign-in', password: pw ?? undefined };
  }
  return { ok: true, detail: r.out.split('\n')[0]?.slice(0, 200) || 'done' };
}

/**
 * Remove one piece of persistence (a filter, forwarding address, delegate, or forwarding
 * itself) from a mailbox. GAM exits 0 on success and 50 when the entity no longer exists —
 * which, for a remove, is the desired end state, so it is reported as done, not failed.
 */
export async function runRemoveAction(
  gamPath: string,
  mailbox: string,
  kind: RemoveKind,
  target: string
): Promise<ActionResult> {
  const args = gamArgsForRemove(kind, mailbox, target);
  if (!args) return { ok: false, detail: 'invalid target or mailbox' };
  const r = await run(gamPath, args);
  if (r.code === 0) return { ok: true, detail: r.out.split('\n').slice(-1)[0]?.slice(0, 200) || 'removed' };
  if (r.code === 50 || /not\s*found|does not exist|invalid delegate/i.test(r.out)) {
    return { ok: true, detail: 'already gone (nothing to remove)' };
  }
  return { ok: false, detail: r.out.split('\n').slice(0, 3).join(' ').slice(0, 300) || `gam exit ${r.code}` };
}

/** Whether the account is currently suspended, so the panel offers Suspend vs Un-suspend. */
export async function userSuspended(gamPath: string, mailbox: string): Promise<boolean | null> {
  const args = gamArgsForAction('suspend', mailbox) ? ['info', 'user', mailbox.trim().toLowerCase(), 'fields', 'suspended'] : null;
  if (!args) return null;
  const r = await run(gamPath, args, 30_000);
  if (r.code !== 0) return null;
  if (/Account Suspended:\s*True/i.test(r.out) || /^Suspended:\s*True/im.test(r.out)) return true;
  if (/Account Suspended:\s*False/i.test(r.out) || /^Suspended:\s*False/im.test(r.out)) return false;
  return null;
}
