/**
 * Job worker.
 *
 * Pinned to globalThis per the Sentinel rule: instrumentation.ts and route handlers
 * do not reliably share a module instance in Next, and a second worker would run
 * every job twice — which for a SWEEP means trashing mail twice and racing its own
 * verify.
 *
 * One job at a time, deliberately. GAM against 1,360 mailboxes is already parallel
 * internally, and two concurrent full-domain scans compete for the same Google API
 * quota. Serial is slower on paper and faster in practice.
 */
import { readFile } from 'node:fs/promises';
import { prisma } from './db';
import { getSettings, notifyRecipients } from './settings';
import { isOwnTraffic } from './hunt';
import { sendMail, sweepNotice, verifyAlert } from './mailer';
import { errText } from './errors';
import {
  runScope, runSweep, runVerify, parseSweepResult, assertSweepSafe,
  protectiveSuffix, ACCOUNT_CHECKS, flagsFromAccountCheck, parseAccountCheck,
  UnsafeQueryError, DestructiveDisabledError, LOG_DIR, labelSwept, sweptMailboxes,
  runTrashSelected, type TrashItem
} from './gam';
import { spawn } from 'node:child_process';
import path from 'node:path';

type G = typeof globalThis & { wardenWorker?: { running: boolean; stop: boolean } };
const g = globalThis as G;

/** Parse a GAM `print messages` CSV into finding rows. */
function parseMessagesCsv(text: string) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return [];
  const header = splitCsv(lines[0]);
  const idx = (n: string) => header.indexOf(n);
  const out: Array<Record<string, string | null>> = [];
  for (let i = 1; i < lines.length; i++) {
    const c = splitCsv(lines[i]);
    if (c.length < 2) continue;
    const from = c[idx('From')] ?? '';
    const m = from.match(/[\w.\-+]+@[\w.\-]+/);
    out.push({
      mailbox: c[idx('User')] ?? null,
      msgId: c[idx('id')] ?? null,
      sender: m ? m[0].toLowerCase() : null,
      subject: c[idx('Subject')] ?? null,
      dateHdr: c[idx('Date')] ?? null,
      labels: idx('Labels') >= 0 ? c[idx('Labels')] ?? null : null
    });
  }
  return out;
}

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

async function readIfExists(p: string): Promise<string> {
  try { return await readFile(p, 'utf8'); } catch { return ''; }
}

async function doScope(job: { id: string; domainKey: string; query: string | null; operatorId: string }) {
  const s = await getSettings(prisma);
  const r = await runScope(s, job.domainKey, job.query ?? '', job.id);
  /**
   * Warden's own alert emails quote the subject of whatever was reported, so a scope on a
   * lure matched them too — 5 of the 10 'findings' on a 2026-10-01 scope were Warden
   * telling admins about the attack. The sweep always excluded them (internal sender), so
   * nothing was ever at risk, but they inflated every count and buried the real copies.
   *
   * Only Warden's own traffic is dropped. [Phish Alert] report copies stay visible: they
   * are the record of who reported, and the sweep already spares them by subject.
   */
  const rows = parseMessagesCsv(await readIfExists(r.logPath)).filter(
    (x) => !isOwnTraffic({ from: String(x.sender ?? ''), subject: x.subject ?? null }, { wardenFrom: s.mail?.from, protectedSubjects: [] })
  );
  if (rows.length) {
    await prisma.wardenFinding.createMany({
      data: rows.map((x) => ({ ...x, jobId: job.id })) as never
    });
  }
  const boxes = new Set(rows.map((x) => x.mailbox)).size;

  // Scope is read-only, but it is a full-text search across every mailbox in a domain and
  // it leaves no other trace. "Who ran a query against all 1,363 staff mailboxes last
  // Tuesday" was previously unanswerable — the audit page claims to record "every
  // destructive action, who ran it, and what it touched", and a domain-wide read is
  // exactly the thing an audit log exists to make accountable.
  const scopeOp = await prisma.wardenUser.findUnique({ where: { id: job.operatorId } });
  await prisma.wardenAudit.create({
    data: {
      operator: scopeOp?.email ?? job.operatorId,
      action: 'scope',
      target: s.domains[job.domainKey],
      query: job.query,
      resultCount: rows.length,
      detail: `${rows.length} messages across ${boxes} mailboxes${r.timedOut ? ' (TIMED OUT — partial)' : ''}`
    }
  }).catch(() => undefined);

  // A partial enumeration is not a measurement. runOne turns a non-zero exit or a timeout
  // into INCOMPLETE, which closes the sweep gate — you cannot decide to delete mail from a
  // count that stopped counting.
  return {
    exitCode: r.exitCode,
    timedOut: r.timedOut,
    completed: r.completed,
    logPath: r.logPath,
    summary: r.timedOut
      ? `TIMED OUT after ${s.scanTimeoutSeconds}s — ${rows.length} messages captured before the cutoff. This is a floor, not a total.`
      : !r.completed
        ? `GAM exited ${r.exitCode} — ${rows.length} messages captured before it stopped. This is a floor, not a total.`
        : `${rows.length} messages across ${boxes} mailboxes`
  };
}

/**
 * Hand-picked containment: label + trash an exact set of messages the operator ticked on a
 * scope result. No query, no domain walk — GAM acts on named ids in named mailboxes, so this
 * is both faster and narrower than a query sweep. Audited (with the operator's reason), and a
 * mailbox whose trash did not exit cleanly is surfaced as a failure, never counted as done.
 */
async function doTrashSelected(
  job: { id: string; domainKey: string; operatorId: string },
  items: TrashItem[],
  reason: string
) {
  const s = await getSettings(prisma);
  const res = await runTrashSelected(s, items);
  const op = await prisma.wardenUser.findUnique({ where: { id: job.operatorId } });
  const completed = res.failures.length === 0;

  await prisma.wardenAudit.create({
    data: {
      operator: op?.email ?? job.operatorId,
      action: 'sweep_selected',
      target: s.domains[job.domainKey],
      resultCount: res.trashed,
      detail:
        `hand-picked: trashed ${res.trashed}/${res.requested} selected message(s) across ${res.mailboxes} mailbox(es)` +
        (res.failures.length ? ` — FAILURES: ${res.failures.join('; ')}` : '') +
        (reason ? ` — reason: ${reason}` : '')
    }
  }).catch(() => undefined);

  const labelNote = (s.sweepWarningLabel ?? '').trim() ? ', marked with the warning label' : '';
  return {
    exitCode: completed ? 0 : 1,
    timedOut: false,
    completed,
    logPath: '',
    summary: completed
      ? `trashed ${res.trashed} hand-picked message(s) across ${res.mailboxes} mailbox(es)${labelNote}${reason ? ` — ${reason}` : ''}`
      : `PARTIAL — ${res.trashed}/${res.requested} trashed; FAILURES: ${res.failures.join('; ')}. Re-run for the mailboxes that failed.`
  };
}

async function doSweep(job: {
  id: string; domainKey: string; query: string | null; operatorId: string; argsJson: string | null;
}) {
  // Hand-picked mode: the operator ticked exact messages on a scope result, so the job carries
  // an id list instead of a query. Trash those by (mailbox, id) — explicit ids are the narrowest
  // possible target, so there is no query for assertSweepSafe to vet. Any other SWEEP is a
  // normal query sweep and falls through unchanged.
  if (job.argsJson) {
    try {
      const parsed = JSON.parse(job.argsJson);
      if (Array.isArray(parsed?.items) && parsed.items.length) {
        return await doTrashSelected(job, parsed.items as TrashItem[], typeof parsed.reason === 'string' ? parsed.reason : '');
      }
    } catch { /* malformed argsJson: fall through to the query path, which will refuse an empty query */ }
  }

  const s = await getSettings(prisma);
  const q = job.query ?? '';
  assertSweepSafe(q, s); // throws UnsafeQueryError -> REFUSED, never reaches GAM
  const r = await runSweep(s, job.domainKey, q, job.id);
  const out = await readIfExists(r.logPath);
  const { trashed, mailboxes } = parseSweepResult(out);

  // Mark what was trashed. Best-effort: the sweep has already done the part that matters.
  const lab = await labelSwept(s, sweptMailboxes(out), q).catch((e) => ({
    ok: false, labelled: 0, detail: `labelling FAILED: ${errText(e)}`
  }));
  const op = await prisma.wardenUser.findUnique({ where: { id: job.operatorId } });

  await prisma.wardenAudit.create({
    data: {
      operator: op?.email ?? job.operatorId,
      action: 'sweep',
      target: s.domains[job.domainKey],
      query: `${q} ${protectiveSuffix(s)}`.trim(),
      resultCount: trashed,
      detail: `trashed ${trashed} across ${mailboxes} mailboxes; ${lab.detail}`
    }
  });

  // Verification is part of the operation, not a follow-up someone might skip.
  await prisma.wardenJob.create({
    data: {
      kind: 'VERIFY',
      operatorId: job.operatorId,
      domainKey: job.domainKey,
      query: q,
      parentId: job.id
    }
  });

  const msg = sweepNotice(
    {
      operator: op?.email ?? job.operatorId,
      query: q,
      trashed,
      mailboxes,
      domain: s.domains[job.domainKey]
    },
    s.consoleUrl
  );
  await sendMail(s.mail, await notifyRecipients(prisma), msg.subject, msg.text, {
    throttleKey: `sweep-${job.id}`
  }).catch(() => undefined);

  return {
    exitCode: r.exitCode,
    timedOut: r.timedOut,
    completed: r.completed,
    logPath: r.logPath,
    summary:
      r.completed
        ? `trashed ${trashed} messages across ${mailboxes} mailboxes — ${lab.ok ? (lab.labelled ? `${lab.labelled} marked with the warning label` : 'warning label applied') : lab.detail} — verify queued`
        : `PARTIAL SWEEP — GAM ${r.timedOut ? 'was killed at the timeout' : `exited ${r.exitCode}`} after trashing ${trashed} messages across ${mailboxes} mailboxes. Mail matching this query may remain. The verify will say what is left.`
  };
}

async function doVerify(job: {
  id: string; domainKey: string; query: string | null; operatorId: string; parentId: string | null;
}) {
  const s = await getSettings(prisma);
  const r = await runVerify(s, job.domainKey, job.query ?? '', job.id);
  const rows = parseMessagesCsv(await readIfExists(r.logPath));
  if (rows.length) {
    await prisma.wardenFinding.createMany({
      data: rows.map((x) => ({ ...x, jobId: job.id })) as never
    });
  }
  /**
   * THREE outcomes, not two. This is the most important distinction in the file.
   *
   * Zero rows means "nothing survived" ONLY if GAM actually finished. `readIfExists`
   * returns '' on any read error and `parseMessagesCsv` returns [] for anything under two
   * lines, so a GAM killed at the scan timeout partway through 1,363 mailboxes produces
   * exactly the same zero as a genuinely clean sweep.
   *
   * It used to be `const clean = rows.length === 0`, which printed "CLEAN — nothing
   * remains outside Trash" in green and wrote verified = true to the audit log for a
   * verification that never ran. That is the founding incident of this codebase —
   * "a bulk sweep reported success while one copy survived" — rebuilt inside the check
   * that exists to catch it.
   *
   * An unknown is not a pass. It alerts, exactly like survivors do.
   */
  const gamOk = r.completed;
  const clean = gamOk && rows.length === 0;
  const unknown = !gamOk;

  const op = await prisma.wardenUser.findUnique({ where: { id: job.operatorId } });
  const detail = unknown
    ? `INCONCLUSIVE — GAM ${r.timedOut ? `was killed at the ${s.scanTimeoutSeconds}s timeout` : `exited ${r.exitCode}`}; ${rows.length} rows parsed before it stopped. This is NOT a clean result.`
    : clean
      ? 'clean'
      : `${rows.length} copies survived the sweep`;

  await prisma.wardenAudit.create({
    data: {
      operator: op?.email ?? job.operatorId,
      action: 'verify',
      target: s.domains[job.domainKey],
      query: job.query,
      resultCount: rows.length,
      // Only a completed, empty verify is a verification. Never record an unknown as one.
      verified: clean,
      detail
    }
  });

  // Alert on survivors AND on inconclusive runs. A clean verify is the expected outcome
  // and is the only one that stays quiet — silence must mean "checked and clear", never
  // "could not check".
  if (!clean) {
    const msg = verifyAlert(
      {
        query: job.query ?? '',
        survivors: rows.length,
        domain: s.domains[job.domainKey],
        inconclusive: unknown
      },
      s.consoleUrl
    );
    await sendMail(s.mail, await notifyRecipients(prisma), msg.subject, msg.text, {
      throttleKey: `verify-${job.id}`
    }).catch(() => undefined);
  }

  return {
    exitCode: r.exitCode,
    timedOut: r.timedOut,
    completed: r.completed,
    logPath: r.logPath,
    summary: unknown
      ? `INCONCLUSIVE — verify did not complete (${r.timedOut ? 'timed out' : `exit ${r.exitCode}`}). Re-run it; do not treat this as clean.`
      : clean
        ? 'CLEAN — nothing remains outside Trash'
        : `${rows.length} copies STILL PRESENT outside Trash`
  };
}

async function doAccountCheck(job: { id: string; argsJson: string | null; operatorId: string }) {
  const s = await getSettings(prisma);
  const args = JSON.parse(job.argsJson ?? '{}');
  const user: string = args.user;
  let blob = '';
  const failed: string[] = [];
  let timedOut = false;

  for (const c of ACCOUNT_CHECKS) {
    const r = await gamCapture(s.gamPath, c.args(user));
    blob += `===== ${c.name} (exit ${r.exitCode}${r.timedOut ? ', TIMED OUT' : ''}) =====\n${r.text}\n`;
    // Each sub-check is a separate persistence mechanism. If the delegates check failed,
    // we know nothing about delegates — and "clean" over six checks where one never ran
    // is a false negative on the exact thing that survives a password reset.
    // 60 = NO_ENTITIES_FOUND: "this user has no filters" is an answer, not a failure.
    if (r.timedOut || (r.exitCode !== 0 && r.exitCode !== 60)) failed.push(c.name);
    if (r.timedOut) timedOut = true;
  }

  const logPath = path.join(LOG_DIR, `${job.id}.out`);
  await (await import('node:fs/promises')).writeFile(logPath, blob, 'utf8');
  const flags = flagsFromAccountCheck(blob);
  const report = parseAccountCheck(blob);

  // Enumerating one named person's filters, delegates, app passwords and OAuth grants is
  // among the most invasive things this console does, and it left no audit trace at all.
  const acOp = await prisma.wardenUser.findUnique({ where: { id: job.operatorId } });
  await prisma.wardenAudit.create({
    data: {
      operator: acOp?.email ?? job.operatorId,
      action: 'account_check',
      target: user,
      resultCount: flags.length,
      detail: failed.length
        ? `checks that did not complete: ${failed.join(', ')}`
        : flags.length
          ? flags.join(', ')
          : 'no persistence indicators'
    }
  }).catch(() => undefined);

  // A verdict first, then every mechanism by name — "Filters: none, Forwarding: off, …" —
  // so the one-line summary already says clean vs review, and the job page shows the detail.
  const line = report.mechanisms.map((m) => `${m.name}: ${m.summary}`).join(' · ');
  const summary = failed.length
    ? `INCONCLUSIVE — ${failed.join(', ')} did not complete, so this is not a clean result. ${line}`
    : report.verdict === 'review'
      ? `REVIEW — ${line}`
      : `CLEAN — no filters, forwarding, delegates, app passwords, or mail-capable apps you need to question. ${line}`;

  return { exitCode: failed.length ? 1 : 0, timedOut, completed: failed.length === 0, logPath, summary };
}

/**
 * Both streams are drained, so this cannot deadlock the way a bare `spawn` would.
 *
 * It now also returns whether the command SUCCEEDED. It used to resolve with whatever text
 * it had and discard the exit code entirely, so a GAM that failed produced a short error
 * string, matched none of the persistence patterns, and was reported as
 * "clean — no persistence indicators" for an account nobody had actually checked.
 */
function gamCapture(
  gamPath: string,
  args: string[]
): Promise<{ text: string; exitCode: number; timedOut: boolean }> {
  return new Promise((resolve) => {
    let out = '';
    let timedOut = false;
    const c = spawn(gamPath, args);
    const timer = setTimeout(() => {
      timedOut = true;
      c.kill('SIGKILL');
    }, 300_000);
    c.stdout.on('data', (d) => (out += d));
    c.stderr.on('data', (d) => (out += d));
    c.on('error', (e) => {
      clearTimeout(timer);
      resolve({ text: `ERROR: ${e.message}`, exitCode: -1, timedOut });
    });
    c.on('close', (code) => {
      clearTimeout(timer);
      resolve({ text: out, exitCode: code ?? -1, timedOut });
    });
  });
}

async function runOne(): Promise<boolean> {
  const job = await prisma.wardenJob.findFirst({
    where: { status: 'QUEUED' },
    orderBy: { createdAt: 'asc' }
  });
  if (!job) return false;

  await prisma.wardenJob.update({
    where: { id: job.id },
    data: { status: 'RUNNING', startedAt: new Date() }
  });

  try {
    let res: { exitCode: number; timedOut: boolean; completed: boolean; logPath: string; summary: string };
    switch (job.kind) {
      case 'SCOPE': res = await doScope(job); break;
      case 'SWEEP': res = await doSweep(job); break;
      case 'VERIFY': res = await doVerify(job); break;
      case 'ACCOUNT_CHECK': res = await doAccountCheck(job); break;
      default: throw new Error(`unknown job kind ${job.kind}`);
    }

    /**
     * DONE means GAM finished. It used to mean "the function returned", which is not the
     * same thing and never was: `status: 'DONE'` was set unconditionally while
     * `res.exitCode` was stored and never read by anything.
     *
     * The consequence was a green DONE on a scope GAM had aborted after 12 of 1,363
     * mailboxes, complete with a live "Trash 12 messages" button. INCOMPLETE closes that
     * gate — see the SCOPE branch on the job page.
     */
    const finished = res.completed;
    await prisma.wardenJob.update({
      where: { id: job.id },
      data: {
        status: finished ? 'DONE' : 'INCOMPLETE',
        finishedAt: new Date(),
        exitCode: res.exitCode,
        timedOut: res.timedOut,
        summary: res.summary,
        logPath: res.logPath
      }
    });
  } catch (e) {
    const refused = e instanceof UnsafeQueryError || e instanceof DestructiveDisabledError;
    await prisma.wardenJob.update({
      where: { id: job.id },
      data: {
        status: refused ? 'REFUSED' : 'ERROR',
        finishedAt: new Date(),
        summary: errText(e, 500)
      }
    });
    if (refused) {
      const op = await prisma.wardenUser.findUnique({ where: { id: job.operatorId } });
      await prisma.wardenAudit.create({
        data: {
          operator: op?.email ?? job.operatorId,
          action: 'sweep_refused',
          query: job.query,
          detail: errText(e, 500)
        }
      });
    }
  }
  return true;
}

export function startWorker() {
  if (g.wardenWorker?.running) return;
  g.wardenWorker = { running: true, stop: false };

  void (async () => {
    /**
     * Anything left RUNNING is from a process that died mid-job.
     *
     * Split by kind, because the consequences are not remotely the same. An interrupted
     * SCOPE or VERIFY is a read that has to be repeated. An interrupted SWEEP means GAM
     * was trashing mail when the process died: an unknown number of messages were removed
     * and there is no summary, because the summary is written after GAM returns. That
     * needs to say so, loudly, rather than sharing wording with a failed read.
     */
    await prisma.wardenJob
      .updateMany({
        where: { status: 'RUNNING', kind: { not: 'SWEEP' } },
        data: {
          status: 'ERROR',
          summary: 'interrupted — the service restarted mid-job. Nothing was written; run it again.'
        }
      })
      .catch(() => undefined);

    await prisma.wardenJob
      .updateMany({
        where: { status: 'RUNNING', kind: 'SWEEP' },
        data: {
          status: 'ERROR',
          summary:
            'INTERRUPTED MID-SWEEP — the service restarted while GAM was trashing mail. ' +
            'An unknown number of messages were removed and no count was recorded. Run a ' +
            'VERIFY against the same query to establish what is actually left before ' +
            'sweeping again.'
        }
      })
      .catch(() => undefined);

    while (!g.wardenWorker?.stop) {
      try {
        const did = await runOne();
        if (!did) await new Promise((r) => setTimeout(r, 2000));
      } catch {
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
    if (g.wardenWorker) g.wardenWorker.running = false;
  })();
}
