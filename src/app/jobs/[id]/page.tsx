import { redirect, notFound } from 'next/navigation';
import { fmtTs, fmtClock } from '@/lib/time';
import { revalidatePath } from 'next/cache';
import Link from 'next/link';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings, destructiveAllowed } from '@/lib/settings';
import { assertSweepSafe, protectiveSuffix, UnsafeQueryError, parseAccountCheck, parseRemovableItems, LOG_DIR } from '@/lib/gam';
import { ShieldAlert, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { RESPONSE_ACTIONS, isResponseAction, isRemoveKind, type ResponseAction, type RemoveKind } from '@/lib/response-actions';
import { runUserAction, runRemoveAction, userSuspended } from '@/lib/user-actions';
import { holdOnce, takeOnce } from '@/lib/onetime';
import { ConfirmAction } from '@/components/ConfirmAction';
import { Live } from './Live';
import { HOST_CMD } from '@/lib/runtime';
import { readProgress } from '@/lib/progress';

export const dynamic = 'force-dynamic';

/**
 * Job detail, and the only place a SWEEP can be created.
 *
 * The preview gate is the point: a sweep is born from a completed SCOPE, showing the
 * operator exactly which senders and how many mailboxes they are about to touch. On
 * 2026-09-22 a sender-scoped sweep would have destroyed 51 live IEP messages; the
 * difference between that and a clean removal was looking first.
 */
/**
 * Why these exist as rendered text rather than as a redirect nobody sees: the server
 * action redirects to `?error=…` on refusal, and this page used to declare only `params`.
 * The failure path therefore re-rendered the page byte-identical — no message, no cleared
 * field. An operator who typed `sweep` instead of `SWEEP` got silence, concluded the click
 * had not registered, and clicked again, while mail was still being delivered.
 */
const ERRORS: Record<string, string> = {
  respconfirm: 'Nothing was done. The confirmation text did not match the mailbox exactly.',
  respforbidden: 'Nothing was done. Response actions require the RESPONDER or ADMIN role.',
  badaction: 'Nothing was done. Unknown action.',
  confirm:
    'Not swept. The confirmation must be exactly SWEEP — upper case, no spaces. Nothing was ' +
    'queued and no mail was touched.',
  role: 'Not swept. Your role is ANALYST, which is read-only. A RESPONDER or ADMIN must run it.',
  toolate:
    'Too late to cancel — the worker had already started this job. It will run to ' +
    'completion; the result appears here when it finishes.',
  nosweepretry:
    'A sweep is never re-run from a button. Open the scope it came from and pass the ' +
    'preview gate again, with the current counts in front of you.',
  nopick: 'Nothing was done. No messages were selected.',
  reason: 'Nothing was done. A reason is required so the audit records why these were removed.'
};

const REMOVE_LABEL: Record<RemoveKind, string> = {
  filter: 'Filter',
  forwardingaddress: 'Forwarding address',
  delegate: 'Delegate',
  forward_off: 'Forwarding'
};

export default async function JobPage({
  params,
  searchParams
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ error?: string; resp?: string; respmsg?: string; respok?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { id } = await params;
  const { error, resp, respmsg, respok } = await searchParams;

  const job = await prisma.wardenJob.findUnique({
    where: { id },
    include: { operator: { select: { email: true } }, children: true }
  });
  if (!job) notFound();

  const [stats, senders, sample] = await Promise.all([
    prisma.wardenFinding.aggregate({ where: { jobId: id }, _count: true }),
    prisma.wardenFinding.groupBy({
      by: ['sender'], where: { jobId: id }, _count: true,
      orderBy: { _count: { sender: 'desc' } }, take: 20
    }),
    prisma.wardenFinding.findMany({ where: { jobId: id }, take: 10 })
  ]);
  const mailboxes = await prisma.wardenFinding
    .findMany({ where: { jobId: id }, select: { mailbox: true }, distinct: ['mailbox'] })
    .then((r) => r.length);

  // The hand-picked containment list: every finding with a real mailbox and Gmail id, so the
  // operator can tick exact messages instead of crafting a query. Capped — a selection of
  // hundreds is a query's job, not a checkbox's.
  const PICK_CAP = 500;
  const pickable =
    job.kind === 'SCOPE' && job.status === 'DONE' && stats._count > 0
      ? await prisma.wardenFinding.findMany({
          where: { jobId: id, msgId: { not: null }, mailbox: { not: null } },
          select: { id: true, mailbox: true, sender: true, subject: true, dateHdr: true },
          orderBy: [{ mailbox: 'asc' }, { dateHdr: 'desc' }],
          take: PICK_CAP + 1
        })
      : [];
  const pickableTruncated = pickable.length > PICK_CAP;
  const pickRows = pickable.slice(0, PICK_CAP);

  // Who an ANALYST should call. /users is ADMIN-gated, so without this the role refusal
  // is a dead end at exactly the moment someone needs an answer.
  const responders = await prisma.wardenUser.findMany({
    where: { role: { in: ['RESPONDER', 'ADMIN'] }, disabled: false },
    select: { email: true },
    orderBy: { email: 'asc' },
    take: 8
  });

  const s = await getSettings(prisma);

  // The worker runs one job at a time, so 'queued' can mean 'waiting behind a 15-minute
  // scan'. Saying which is the difference between patience and a second click.
  const queuedAhead =
    job.status === 'QUEUED'
      ? await prisma.wardenJob.count({
          where: { status: { in: ['QUEUED', 'RUNNING'] }, createdAt: { lt: job.createdAt } }
        })
      : 0;

  // Would this query be accepted as a sweep? Compute it now so the operator sees the
  // refusal reason BEFORE clicking, not after.
  let sweepBlocked: string | null = null;
  if (job.query) {
    try {
      assertSweepSafe(job.query, s);
    } catch (e) {
      sweepBlocked = e instanceof UnsafeQueryError ? e.message : String(e);
    }
  }
  if (!destructiveAllowed()) {
    sweepBlocked =
      'Destructive operations are disabled on this host. Sweeps are refused until ' +
      `${HOST_CMD.gateWhere} is set to 1 and the service restarted.`;
  }

  async function createSweep(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect(`/jobs/${id}?error=role`);
    // Trimmed, because a trailing space from a paste is a typo, not a decision. The exact
    // upper-case match is kept — the friction is the point — but the failure is now
    // rendered, which it never used to be.
    const confirm = String(formData.get('confirm') ?? '').trim();
    if (confirm !== 'SWEEP') redirect(`/jobs/${id}?error=confirm`);

    const parent = await prisma.wardenJob.findUnique({ where: { id } });
    if (!parent?.query) redirect(`/jobs/${id}`);

    const sweep = await prisma.wardenJob.create({
      data: {
        kind: 'SWEEP', operatorId: u.id, domainKey: parent.domainKey,
        query: parent.query, parentId: parent.id
      }
    });
    revalidatePath('/jobs');
    redirect(`/jobs/${sweep.id}`);
  }

  /**
   * Hand-picked containment. The operator ticked exact messages on this scope result; trash
   * those by their (mailbox, Gmail id), labelled, via a SWEEP job carrying an id list instead
   * of a query (see doSweep's argsJson branch). Explicit ids are the narrowest possible target,
   * so there is no query to craft and nothing for assertSweepSafe to refuse — the thing that
   * made a hand-typed sender-only query a dead end. The mailbox and id for each pick are read
   * from the database here, never trusted from the form.
   */
  async function createTrashSelected(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect(`/jobs/${id}?error=role`);
    if (process.env.WARDEN_ALLOW_DESTRUCTIVE !== '1') redirect(`/jobs/${id}`);
    if (String(formData.get('confirm') ?? '').trim() !== 'SWEEP') redirect(`/jobs/${id}?error=confirm`);
    const reason = String(formData.get('reason') ?? '').trim();
    if (!reason) redirect(`/jobs/${id}?error=reason`);

    const picked = formData.getAll('pick').map(String).filter(Boolean);
    if (!picked.length) redirect(`/jobs/${id}?error=nopick`);

    // Resolve the picks to (mailbox, id) from the database — only rows that belong to THIS
    // scope and carry a real mailbox and Gmail id. The browser never decides what gets trashed.
    const rows = await prisma.wardenFinding.findMany({
      where: { id: { in: picked.slice(0, 500) }, jobId: id, msgId: { not: null }, mailbox: { not: null } },
      select: { mailbox: true, msgId: true }
    });
    const items = rows.map((r) => ({ mailbox: r.mailbox as string, id: r.msgId as string }));
    if (!items.length) redirect(`/jobs/${id}?error=nopick`);

    const parent = await prisma.wardenJob.findUnique({ where: { id } });
    const job = await prisma.wardenJob.create({
      data: {
        kind: 'SWEEP', operatorId: u.id, domainKey: parent?.domainKey ?? 'staff',
        parentId: id, argsJson: JSON.stringify({ items, reason })
      }
    });
    revalidatePath('/jobs');
    redirect(`/jobs/${job.id}`);
  }

  /**
   * Withdraw a job that has not started. Guarded by a conditional update rather than a
   * read-then-write: the worker polls every few seconds, so between rendering this page
   * and the click landing the job may already be RUNNING. `updateMany` with
   * `status: 'QUEUED'` in the where clause makes the check and the write one atomic
   * operation — if it matched nothing, the worker won the race and nothing is claimed.
   */
  async function cancelJob() {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect(`/jobs/${id}?error=role`);

    const res = await prisma.wardenJob.updateMany({
      where: { id, status: 'QUEUED' },
      data: { status: 'CANCELLED', finishedAt: new Date(), summary: `Cancelled by ${u.email} before it started.` }
    });
    if (res.count) {
      await prisma.wardenAudit.create({
        data: { operator: u.email, action: 'job_cancelled', target: id, resultCount: 0 }
      });
    }
    revalidatePath(`/jobs/${id}`);
    revalidatePath('/jobs');
    if (!res.count) redirect(`/jobs/${id}?error=toolate`);
  }

  /**
   * Re-run this job with the same parameters.
   *
   * SWEEP is deliberately excluded. Everything else here is a read that can be repeated
   * freely, but a one-click "run again" on mail deletion would hand somebody a way to
   * trash a domain without passing the preview gate — which is the single control this
   * console is built around. A sweep is always re-authorised from its parent scope, by
   * typing SWEEP, with the counts in front of you.
   *
   * Read-only by nature, so no role gate beyond "can create this kind of job at all":
   * an ANALYST can already run a scope from /scope, and a retry is the same act.
   */
  async function retryJob() {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');

    const parent = await prisma.wardenJob.findUnique({ where: { id } });
    if (!parent) redirect('/jobs');
    if (parent.kind === 'SWEEP') redirect(`/jobs/${id}?error=nosweepretry`);

    const again = await prisma.wardenJob.create({
      data: {
        kind: parent.kind,
        operatorId: u.id,
        domainKey: parent.domainKey,
        query: parent.query,
        argsJson: parent.argsJson,
        // Keep a VERIFY attached to the sweep it verifies, so the chain stays readable.
        parentId: parent.kind === 'VERIFY' ? parent.parentId : null
      }
    });
    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: 'job_rerun',
        target: s.domains[parent.domainKey] ?? parent.domainKey,
        query: parent.query,
        detail: `re-ran ${parent.kind} ${parent.id} as ${again.id}`
      }
    }).catch(() => undefined);

    revalidatePath('/jobs');
    redirect(`/jobs/${again.id}`);
  }

  /**
   * Run a response action (sign out, deprovision, reset password, suspend, un-suspend)
   * against the account this check was about. RESPONDER or ADMIN only. The typed mailbox is
   * re-checked here, not only in the browser, so the confirmation is a real gate rather than
   * a client-side nicety. A reset password is handed back through a one-time token, never in
   * the URL or the database.
   */
  async function runResponse(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect(`/jobs/${id}?error=respforbidden`);

    const action = String(formData.get('action') ?? '');
    const mailbox = String(formData.get('mailbox') ?? '').trim().toLowerCase();
    const confirm = String(formData.get('confirm') ?? '').trim().toLowerCase();
    if (!isResponseAction(action)) redirect(`/jobs/${id}?error=badaction`);
    if (!mailbox || confirm !== mailbox) redirect(`/jobs/${id}?error=respconfirm`);

    const def = RESPONSE_ACTIONS[action as ResponseAction];
    const result = await runUserAction(s.gamPath, mailbox, action as ResponseAction);

    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: `user_${action}`,
        target: mailbox,
        detail: result.ok ? `${def.done}` : `FAILED: ${result.detail}`
      }
    }).catch(() => undefined);

    const msg = result.ok ? `${mailbox} — ${def.done}.` : `Could not ${def.label.toLowerCase()}: ${result.detail}`;
    const params = new URLSearchParams({ respmsg: msg, respok: result.ok ? '1' : '0' });
    if (result.password) params.set('resp', holdOnce(result.password));
    revalidatePath(`/jobs/${id}`);
    redirect(`/jobs/${id}?${params.toString()}`);
  }

  /**
   * Remove one piece of persistence the check found — a filter, forwarding address, delegate,
   * or forwarding itself. Same gate as the other account actions (RESPONDER/ADMIN, typed-mailbox
   * confirm) plus a required reason captured to the audit. The target (filter id / address) is
   * passed from the rendered item, but the action is the narrowest possible GAM mutation and the
   * mailbox is re-confirmed here, so a bad value just fails to build a command.
   */
  async function removePersistence(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect(`/jobs/${id}?error=respforbidden`);

    const mailbox = String(formData.get('mailbox') ?? '').trim().toLowerCase();
    const confirm = String(formData.get('confirm') ?? '').trim().toLowerCase();
    const kind = String(formData.get('kind') ?? '');
    const target = String(formData.get('target') ?? '');
    const reason = String(formData.get('reason') ?? '').trim();
    if (!isRemoveKind(kind)) redirect(`/jobs/${id}?error=badaction`);
    if (!mailbox || confirm !== mailbox) redirect(`/jobs/${id}?error=respconfirm`);
    if (!reason) redirect(`/jobs/${id}?error=reason`);

    const result = await runRemoveAction(s.gamPath, mailbox, kind as RemoveKind, target);

    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: `remove_${kind}`,
        target: mailbox,
        detail:
          `${result.ok ? 'removed' : 'FAILED'}: ${kind}${target ? ` ${target}` : ''}` +
          `${result.ok ? '' : ` — ${result.detail}`} — reason: ${reason}`
      }
    }).catch(() => undefined);

    const msg = result.ok
      ? `${mailbox} — removed ${kind}${target ? ` ${target}` : ''}. Re-run the account check to confirm it is clean.`
      : `Could not remove ${kind}: ${result.detail}`;
    const params = new URLSearchParams({ respmsg: msg, respok: result.ok ? '1' : '0' });
    revalidatePath(`/jobs/${id}`);
    redirect(`/jobs/${id}?${params.toString()}`);
  }

  // Account-check response panel data: the mailbox, and whether it is currently suspended.
  const acMailbox = job.kind === 'ACCOUNT_CHECK'
    ? (job.query || (() => { try { return JSON.parse(job.argsJson ?? '{}').user as string; } catch { return ''; } })())
    : '';
  const acSuspended = acMailbox && user.role !== 'ANALYST' && (job.status === 'DONE' || job.status === 'INCOMPLETE')
    ? await userSuspended(s.gamPath, acMailbox).catch(() => null)
    : null;
  const newPassword = takeOnce(resp);

  const badge =
    job.status === 'DONE' ? 'pill-ok'
    : job.status === 'ERROR' || job.status === 'REFUSED' ? 'pill-critical'
    : job.status === 'INCOMPLETE' ? 'pill-high'
    : 'pill-medium';

  // GAM ran but did not finish. Partial output is not a result, and this is the fact the
  // whole page now turns on: no sweep gate, no "verified clean", no green anything.
  const incomplete = job.status === 'INCOMPLETE';
  const domain = s.domains[job.domainKey] ?? job.domainKey;

  // For an account check, parse the raw GAM output into a per-mechanism breakdown so the
  // page can say plainly "clean" vs "review these", with the detail behind each line.
  const acBlob =
    job.kind === 'ACCOUNT_CHECK' && (job.status === 'DONE' || job.status === 'INCOMPLETE')
      ? await readFile(path.join(LOG_DIR, `${job.id}.out`), 'utf8').catch(() => '')
      : '';
  const acReport = acBlob ? parseAccountCheck(acBlob) : null;
  // The filters/forwarding/delegates a check found, as removable items. Responder/admin only;
  // an analyst sees the findings but not the remove controls.
  const removableItems = acBlob && acMailbox && user.role !== 'ANALYST' ? parseRemovableItems(acBlob) : [];

  return (
    <div className="max-w-5xl space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
            {job.kind}
            <span className={`pill ${badge}`}>{job.status}</span>
            {/* The population. 1,360 mailboxes and 6,300 are different decisions, and this
                was previously not rendered anywhere in the console at all. */}
            <span className="mono pill pill-muted">{domain}</span>
          </h1>
          <p className="mono mt-1 text-sm text-text-muted">{job.query}</p>
        </div>
        <div className="text-right text-xs text-text-muted">
          <div>{job.operator.email.split('@')[0]}</div>
          <div>{fmtTs(job.createdAt)}</div>
          {job.exitCode !== null && (
            <div>
              GAM exit {job.exitCode}
              {job.timedOut ? ' · TIMED OUT' : ''}
            </div>
          )}
        </div>
      </header>

      {error && ERRORS[error] && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <strong className="text-danger">{ERRORS[error]}</strong>
        </div>
      )}

      {/* The outcome, promoted out of the 12px corner it used to live in. For a SWEEP this
          is the only statement of what was deleted. */}
      {job.summary && (
        <div
          className="card text-sm"
          style={
            incomplete || job.status === 'ERROR'
              ? { borderColor: 'rgb(var(--danger) / 0.5)' }
              : undefined
          }
        >
          {job.summary}
        </div>
      )}

      {acReport && (
        <div className="card space-y-3">
          <div className="flex items-center gap-2">
            {acReport.verdict === 'clean' ? (
              <><CheckCircle2 size={20} style={{ color: 'rgb(var(--success))' }} /><strong className="text-base">Clean</strong>
              <span className="text-sm text-text-muted">— nothing that persists past a password reset</span></>
            ) : acReport.verdict === 'review' ? (
              <><AlertTriangle size={20} style={{ color: 'rgb(var(--warning))' }} /><strong className="text-base">Review</strong>
              <span className="text-sm text-text-muted">— these are legitimate for most people; confirm you recognise them</span></>
            ) : (
              <><XCircle size={20} style={{ color: 'rgb(var(--danger))' }} /><strong className="text-base">Inconclusive</strong>
              <span className="text-sm text-text-muted">— a check did not complete, so this is not a clean result</span></>
            )}
          </div>

          <table className="w-full border-collapse text-sm">
            <tbody>
              {acReport.mechanisms.map((m) => (
                <tr key={m.name} className="border-b last:border-0 align-top">
                  <td className="td w-6">
                    {m.status === 'clean' ? <CheckCircle2 size={15} style={{ color: 'rgb(var(--success))' }} />
                      : m.status === 'review' ? <AlertTriangle size={15} style={{ color: 'rgb(var(--warning))' }} />
                      : <XCircle size={15} style={{ color: 'rgb(var(--danger))' }} />}
                  </td>
                  <td className="td w-52 font-medium">{m.name}</td>
                  <td className="td">
                    <span className={m.status === 'clean' ? 'text-text-muted' : ''}>{m.summary}</span>
                    {m.detail.length > 0 && (
                      <ul className="mt-0.5 space-y-0.5 text-xs text-text-muted">
                        {m.detail.map((d, i) => <li key={i} className="mono">· {d}</li>)}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {acReport.apps.length > 0 && (
            /* Open by default: a "clean" verdict must SHOW what was checked, not ask the
               operator to take it on faith behind a toggle. This is the list that lets
               "Adobe Acrobat — sign-in only" read as obviously different from a grant that
               can touch mail. It stays a <details> so a long list can still be folded away. */
            <details open className="text-sm">
              <summary className="cursor-pointer text-xs text-text-muted">
                All {acReport.apps.length} connected app{acReport.apps.length === 1 ? '' : 's'} (OAuth) — what each one can do
              </summary>
              <table className="mt-2 w-full border-collapse text-xs">
                <thead><tr className="border-b text-left"><th className="th">App</th><th className="th w-24">Access</th><th className="th">Scopes</th></tr></thead>
                <tbody>
                  {acReport.apps.map((a, i) => (
                    <tr key={i} className="border-b align-top">
                      <td className="td">{a.name}</td>
                      <td className="td">{a.mailAccess ? <span className="pill pill-high">mail</span> : <span className="text-text-muted">sign-in only</span>}</td>
                      <td className="td mono text-text-muted">{a.scopes.join('  ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}

          <p className="text-xs text-text-muted">
            Read-only enumeration of filters, forwarding, delegates, app passwords and OAuth grants — the
            places a takeover hides, because they survive a password reset. A native mail app (Apple Mail,
            Outlook) legitimately holds a mail scope, so &ldquo;review&rdquo; means <em>look</em>, not <em>alarm</em>.
          </p>
        </div>
      )}

      {/* Response actions. Shown on an account check for RESPONDER/ADMIN. Each one opens a
          typed-confirmation popup and is audited; none is automatic. */}
      {acMailbox && user.role !== 'ANALYST' && (job.status === 'DONE' || job.status === 'INCOMPLETE') && (
        <div className="card space-y-3" style={{ borderColor: 'rgb(var(--danger) / 0.35)' }}>
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <ShieldAlert size={16} style={{ color: 'rgb(var(--danger))' }} /> Response actions
              {acSuspended === true && <span className="pill pill-critical">currently suspended</span>}
            </h2>
            <p className="mt-1 text-xs text-text-muted">
              These act on <span className="mono">{acMailbox}</span> immediately. Each one asks you to type the
              mailbox to confirm, and is written to the audit log. For a confirmed takeover, Force sign-out +
              Revoke app passwords + Reset password evicts the attacker while keeping the account alive.
            </p>
          </div>

          {respmsg && (
            <div
              className="rounded border px-3 py-2 text-sm"
              style={{ borderColor: respok === '1' ? 'rgb(var(--success) / 0.5)' : 'rgb(var(--danger) / 0.5)' }}
            >
              {respmsg}
              {newPassword && (
                <div className="mt-2">
                  <div className="text-xs text-text-muted">New password (shown once — copy it now):</div>
                  <div className="mono select-all text-base font-semibold">{newPassword}</div>
                </div>
              )}
            </div>
          )}

          <div className="grid gap-2 sm:grid-cols-2">
            {(['signout', 'deprovision', 'reset'] as const).map((k) => {
              const d = RESPONSE_ACTIONS[k];
              return (
                <div key={k}>
                  <ConfirmAction
                    action={runResponse}
                    mailbox={acMailbox}
                    actionKey={k}
                    label={d.label}
                    blurb={d.blurb}
                    reversible={d.reversible}
                    danger={d.danger === 'high'}
                    confirmText={acMailbox}
                  />
                  <p className="mt-0.5 text-xs text-text-muted">{d.blurb}</p>
                </div>
              );
            })}
            <div>
              {acSuspended === true ? (
                <ConfirmAction action={runResponse} mailbox={acMailbox} actionKey="unsuspend"
                  label={RESPONSE_ACTIONS.unsuspend.label} blurb={RESPONSE_ACTIONS.unsuspend.blurb}
                  reversible={RESPONSE_ACTIONS.unsuspend.reversible} danger={false} confirmText={acMailbox} />
              ) : (
                <ConfirmAction action={runResponse} mailbox={acMailbox} actionKey="suspend"
                  label={RESPONSE_ACTIONS.suspend.label} blurb={RESPONSE_ACTIONS.suspend.blurb}
                  reversible={RESPONSE_ACTIONS.suspend.reversible} danger confirmText={acMailbox} />
              )}
              <p className="mt-0.5 text-xs text-text-muted">
                {acSuspended === true ? RESPONSE_ACTIONS.unsuspend.blurb : RESPONSE_ACTIONS.suspend.blurb}
                {acSuspended === null && ' (current suspend state unknown)'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Remove the persistence the check found — the detect→respond gap this closes. Filters,
          forwarding, delegates and active forwarding, each a one-click remove with a typed
          confirm + reason. Responder/admin only (removableItems is empty otherwise). */}
      {removableItems.length > 0 && (
        <div className="card space-y-3" style={{ borderColor: 'rgb(var(--danger) / 0.35)' }}>
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <ShieldAlert size={16} style={{ color: 'rgb(var(--danger))' }} /> Remove persistence
            </h2>
            <p className="mt-1 text-xs text-text-muted">
              The filters, forwarding and delegates on <span className="mono">{acMailbox}</span> — the access
              that survives a password reset. Remove the hostile ones; each asks you to type the mailbox and a
              reason, and is audited. Leave the legitimate ones (a native mail app, an assistant&rsquo;s
              delegation) in place. Re-run the account check afterwards to confirm it is clean.
            </p>
          </div>
          <ul className="space-y-2">
            {removableItems.map((it, i) => (
              <li key={i} className="flex flex-wrap items-center justify-between gap-2 rounded border p-2 text-xs">
                <span className="min-w-0 break-words">
                  <span className="pill pill-muted mr-2">{REMOVE_LABEL[it.kind]}</span>
                  <span className="mono">{it.label}</span>
                </span>
                <ConfirmAction
                  action={removePersistence}
                  mailbox={acMailbox}
                  actionKey={it.kind}
                  label={`Remove ${REMOVE_LABEL[it.kind].toLowerCase()}`}
                  blurb={
                    it.kind === 'forward_off'
                      ? `This turns OFF auto-forwarding on ${acMailbox}.`
                      : `This removes the ${REMOVE_LABEL[it.kind].toLowerCase()} "${it.label}" from ${acMailbox}.`
                  }
                  reversible="A legitimate one can be re-created by the user afterwards."
                  danger
                  confirmText={acMailbox}
                  extraFields={{ kind: it.kind, target: it.target }}
                  requireReason
                />
              </li>
            ))}
          </ul>
        </div>
      )}

      {incomplete && (
        <div className="card flex items-start gap-2 text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <XCircle size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--danger))' }} />
          <div>
            <strong className="text-danger">GAM did not finish. These results are partial.</strong>
            <p className="mt-1 text-text-muted">
              {job.timedOut
                ? `It was killed at the ${s.scanTimeoutSeconds}-second scan timeout.`
                : `It exited with code ${job.exitCode}.`}{' '}
              Any count shown is a floor, not a total &mdash; it stopped counting partway
              through {domain}. Re-run it before deciding anything.
              {job.kind === 'SCOPE' && ' The sweep gate stays closed until a scope completes.'}
            </p>
          </div>
        </div>
      )}

      {(job.status === 'QUEUED' || job.status === 'RUNNING') && (
        <>
          <Live
            startedAt={job.startedAt ? job.startedAt.toISOString() : null}
            status={job.status}
            expectedSeconds={s.scanTimeoutSeconds}
            queuedAhead={queuedAhead}
            progress={job.status === 'RUNNING' ? await readProgress(job.id) : null}
          />
          {job.status === 'QUEUED' && user.role !== 'ANALYST' && (
            <form action={cancelJob}>
              <button className="btn btn-verdict text-xs">Cancel this job</button>
              <span className="ml-2 text-xs text-text-muted">
                Only possible before it starts. Once GAM is running, a sweep must finish so
                that the verify can establish what it actually touched.
              </span>
            </form>
          )}
        </>
      )}

      {/*
        ERROR previously had no treatment at all — REFUSED got a full red card and a crash
        mid-run got a pill and a line of muted corner text, so the louder-looking outcome
        was the one where nothing had happened.
      */}
      {job.status === 'ERROR' && (
        <div className="card flex items-start gap-2 text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <XCircle size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--danger))' }} />
          <div>
            <strong className="text-danger">
              {job.kind === 'SWEEP' ? 'This sweep did not finish.' : 'This job failed.'}
            </strong>
            <p className="mt-1 text-text-muted">{job.summary}</p>
          </div>
        </div>
      )}

      {/*
        Re-run. Offered for every terminal state except REFUSED, which would fail the same
        gate again, and never for a SWEEP.
      */}
      {job.kind !== 'SWEEP' &&
        ['DONE', 'INCOMPLETE', 'ERROR', 'CANCELLED'].includes(job.status) && (
          <form action={retryJob} className="flex flex-wrap items-center gap-3">
            <button className="btn text-xs">
              {job.status === 'DONE' ? `Run this ${job.kind.toLowerCase()} again` : 'Try again'}
            </button>
            <span className="text-xs text-text-muted">
              {job.status === 'DONE'
                ? 'Same query, same domain, fresh results — mail arrives continuously, so a scope goes out of date.'
                : `Queues a new ${job.kind} with the same query against ${domain}. This one is read-only; nothing is deleted.`}
            </span>
          </form>
        )}

      {job.kind === 'SWEEP' && ['ERROR', 'INCOMPLETE'].includes(job.status) && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--warning) / 0.5)' }}>
          <strong className="text-warning">There is no re-run button for a sweep.</strong>
          <p className="mt-1 text-text-muted">
            An interrupted sweep may have trashed an unknown number of messages, so the
            question is not &ldquo;run it again&rdquo; but &ldquo;what is actually left&rdquo;.
            Run a VERIFY against this query first
            {job.parentId && (
              <>
                {' '}
                &mdash; or open{' '}
                <Link href={`/jobs/${job.parentId}`} className="underline">
                  the scope this came from
                </Link>{' '}
                to re-measure and pass the gate again
              </>
            )}
            . A one-click repeat of mail deletion would bypass the preview, which is the one
            control this console is built around.
          </p>
        </div>
      )}

      {job.status === 'CANCELLED' && (
        <div className="card text-sm">
          <strong>Cancelled before it started.</strong>{' '}
          <span className="text-text-muted">Nothing reached GAM and no mail was touched.</span>
        </div>
      )}

      {job.status === 'REFUSED' && (
        <div className="card flex items-start gap-2 text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.4)' }}>
          <XCircle size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--danger))' }} />
          <div>
            <strong className="text-danger">Refused before reaching GAM.</strong>
            <p className="mt-1 text-text-muted">{job.summary}</p>
          </div>
        </div>
      )}

      {/*
        "Verified clean" is a claim, and it requires that the verify actually RAN. Zero
        findings from a GAM that was killed at the timeout is indistinguishable from zero
        findings from a clean domain — and this panel used to render both as a green tick.
        INCOMPLETE is handled by the block above and deliberately never reaches here.
      */}
      {job.kind === 'VERIFY' && job.status === 'DONE' && (
        <div className="card flex items-start gap-2 text-sm">
          {stats._count === 0 ? (
            <CheckCircle2 size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--success))' }} />
          ) : (
            <ShieldAlert size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--danger))' }} />
          )}
          <div>
            <strong>{stats._count === 0 ? 'Verified clean' : `${stats._count} copies survived`}</strong>
            <p className="mt-1 text-text-muted">
              {stats._count === 0
                ? `GAM completed across ${domain} and nothing matching remains outside Trash. ` +
                  'The verify used the same protective exclusions as the sweep, so responder ' +
                  'copies are not counted here.'
                : 'These were not removed by the sweep. Investigate before closing the incident.'}
            </p>
          </div>
        </div>
      )}

      {job.kind === 'VERIFY' && incomplete && (
        <div className="card flex items-start gap-2 text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <ShieldAlert size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--danger))' }} />
          <div>
            <strong className="text-danger">This sweep is NOT verified.</strong>
            <p className="mt-1 text-text-muted">
              The check did not complete, so nothing is confirmed either way. Do not read the
              absence of survivors as their absence &mdash; a sweep once reported success while a
              copy sat unlabelled outside the Inbox, which is the reason this step exists.
              Re-run the verify.
            </p>
          </div>
        </div>
      )}

      {job.status === 'DONE' && stats._count > 0 && (
        <div className="grid gap-4 md:grid-cols-[1fr_1fr]">
          <div className="card">
            <h2 className="mb-2 text-sm font-medium">
              {stats._count} messages · {mailboxes} mailboxes
            </h2>
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr><th className="th">Sender</th><th className="th w-16">Msgs</th></tr>
              </thead>
              <tbody>
                {senders.map((x) => (
                  <tr key={x.sender ?? 'none'} className="border-t">
                    <td className="td mono">{x.sender ?? '—'}</td>
                    <td className="td">{x._count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="card">
            <h2 className="mb-2 text-sm font-medium">Sample</h2>
            <ul className="space-y-1 text-xs">
              {sample.map((m) => (
                <li key={m.id} className="border-t pt-1">
                  <div className="mono text-text-muted">{m.mailbox?.split('@')[0]}</div>
                  <div>{m.subject}</div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/*
        ── the sweep gate ──────────────────────────────────────────────────

        Requires DONE (so INCOMPLETE cannot reach it) AND at least one finding. A gate that
        renders at zero findings offers a live "Trash 0 messages" button off a query that
        matched nothing — and "zero results" is the single most documented failure mode in
        this codebase: a scan for a domain provably present in message bodies returned
        zero. Zero is a reason to re-read the query, never a reason to delete.
      */}
      {job.kind === 'SCOPE' && job.status === 'DONE' && stats._count === 0 && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--warning) / 0.5)' }}>
          <strong className="text-warning">This scope matched nothing, so there is nothing to sweep.</strong>
          <p className="mt-1 text-text-muted">
            GAM completed across {domain} and returned no messages. Before concluding the mail
            is gone, check the query: Gmail cannot reliably match a bare domain inside a URL
            &mdash; a scan for a domain provably present in message bodies returned zero. Scope on
            distinctive lure text instead, and include <code className="mono">in:anywhere</code>.
          </p>
        </div>
      )}

      {job.kind === 'SCOPE' && job.status === 'DONE' && stats._count > 0 && (
        <div className="card space-y-3" style={{ borderColor: 'rgb(var(--danger) / 0.35)' }}>
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <ShieldAlert size={16} style={{ color: 'rgb(var(--danger))' }} />
            Sweep {domain}
          </h2>

          <div className="rounded border p-3 text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.3)' }}>
            <div>
              About to trash mail matching this query in{' '}
              <strong className="mono">{domain}</strong> &mdash; the scope found{' '}
              <strong>{stats._count}</strong> messages across <strong>{mailboxes}</strong>{' '}
              mailboxes
              {job.finishedAt && (
                <> as of {fmtClock(job.finishedAt)}</>
              )}
              .
            </div>
            <ul className="mt-2 space-y-1 text-xs text-text-muted">
              <li>
                The sweep re-runs the query live, so anything that has arrived since the scope
                is also trashed. That count is a snapshot, not a contract.
              </li>
              <li>
                At most <strong>{s.maxToTrashPerMailbox}</strong> messages are removed per
                mailbox. A mailbox holding more than that keeps the remainder &mdash; the verify
                will report them as survivors.
              </li>
              <li>Messages go to Trash, not permanent delete, and Gmail purges Trash after 30 days.</li>
            </ul>
          </div>

          <div className="text-xs text-text-muted">
            <div>Effective query, with responder protections appended:</div>
            <code className="mono mt-1 block rounded bg-bg-elevated p-2">
              {job.query} {protectiveSuffix(s)}
            </code>
            <div className="mt-1">
              Those exclusions are what spare your own warnings and internal mail. The verify
              applies the same ones, so it measures the set the sweep actually touched.
            </div>
          </div>

          {sweepBlocked ? (
            <div className="rounded border p-3 text-sm"
                 style={{ background: 'rgb(var(--danger) / 0.1)', borderColor: 'rgb(var(--danger) / 0.4)' }}>
              {sweepBlocked}
            </div>
          ) : user.role === 'ANALYST' ? (
            <div className="text-sm text-text-muted">
              Your role is ANALYST &mdash; read only. A RESPONDER or ADMIN must run the sweep.
              {/* Naming them matters: /users is ADMIN-gated, so an analyst at 22:00 could
                  not otherwise find out who to call. */}
              {responders.length > 0 && (
                <>
                  {' '}
                  On this console that is:{' '}
                  <span className="mono">{responders.map((r) => r.email).join(', ')}</span>.
                </>
              )}
            </div>
          ) : (
            <form action={createSweep} className="flex items-end gap-3">
              <label className="text-sm">
                <span className="mb-1 block">
                  Type <code className="mono font-bold">SWEEP</code> to confirm
                </span>
                <input
                  name="confirm"
                  required
                  autoComplete="off"
                  className="w-40 rounded border bg-bg-elevated px-3 py-1.5 text-sm mono"
                />
              </label>
              <button className="btn btn-danger">
                Trash matching mail in {domain}
              </button>
            </form>
          )}
          <p className="text-xs text-text-muted">
            A VERIFY job is queued automatically afterwards and will report anything the
            sweep left behind.
          </p>
        </div>
      )}

      {/*
        ── hand-picked containment ─────────────────────────────────────────
        The complement to the query sweep: tick exact messages and they are labelled and
        trashed by their Gmail id. No query to craft, so nothing for the safety rail to
        refuse — a sender-only query getting bounced is the friction this removes. Same
        DONE+findings gate and role/destructive gates as the sweep above.
      */}
      {job.kind === 'SCOPE' && job.status === 'DONE' && pickRows.length > 0 && !sweepBlocked && user.role !== 'ANALYST' && (
        <form action={createTrashSelected} className="card space-y-3">
          <h2 className="text-sm font-semibold">Pick exact messages to label &amp; Trash</h2>
          <p className="text-xs text-text-muted">
            Tick the messages to contain and they are labelled <span className="mono">{s.sweepWarningLabel || '(no label set)'}</span> and
            moved to Trash by their exact Gmail id &mdash; recoverable, kept as evidence. This touches
            only what you tick: no query, nothing to refuse, no other mailbox reached.
          </p>
          <div className="max-h-96 divide-y overflow-y-auto rounded border">
            {pickRows.map((m) => (
              <label key={m.id} className="flex cursor-pointer items-start gap-2 p-2 text-xs hover:bg-bg-elevated">
                <input type="checkbox" name="pick" value={m.id} className="mt-0.5" />
                <span className="min-w-0">
                  <span className="mono text-text-muted">{m.mailbox}</span>
                  {m.dateHdr ? <span className="text-text-muted"> &middot; {m.dateHdr}</span> : null}
                  <span className="block break-words">{m.subject ?? '(no subject)'}</span>
                  {m.sender ? <span className="mono block text-text-muted">{m.sender}</span> : null}
                </span>
              </label>
            ))}
          </div>
          {pickableTruncated && (
            <p className="text-xs text-warning">
              Showing the first {PICK_CAP}. For a larger set, use the query sweep above.
            </p>
          )}
          <div className="flex flex-wrap items-end gap-3">
            <label className="min-w-48 flex-1 text-sm">
              <span className="mb-1 block">Reason / ticket</span>
              <input
                name="reason"
                required
                autoComplete="off"
                placeholder="why these are being removed"
                className="w-full rounded border bg-bg-elevated px-3 py-1.5 text-sm"
              />
            </label>
            <label className="text-sm">
              <span className="mb-1 block">Type <code className="mono font-bold">SWEEP</code></span>
              <input name="confirm" required autoComplete="off" className="w-32 rounded border bg-bg-elevated px-3 py-1.5 text-sm mono" />
            </label>
            <button className="btn btn-danger">Label &amp; Trash selected</button>
          </div>
          <p className="text-xs text-text-muted">
            Recorded in the audit log with your reason. These go straight to Trash by id; no
            domain-wide scan runs.
          </p>
        </form>
      )}

      {job.children.length > 0 && (
        <div className="card text-sm">
          <h2 className="mb-2 font-medium">Follow-up jobs</h2>
          {job.children.map((c) => (
            <a key={c.id} href={`/jobs/${c.id}`} className="block hover:underline">
              {c.kind} · {c.status} · {c.summary ?? 'pending'}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
