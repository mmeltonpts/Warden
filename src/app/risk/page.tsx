import { redirect } from 'next/navigation';
import { fmtTs } from '@/lib/time';
import { revalidatePath } from 'next/cache';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { band } from '@/lib/baseline';
import { getSettings } from '@/lib/settings';
import { PendingButton } from '@/components/PendingButton';

export const dynamic = 'force-dynamic';

/**
 * A student flag is usually a teenager on a VPN, and there are thousands of them. Staff
 * flags are the ones that lead to a district compromise. Separating the two lets an
 * operator clear the predictable noise in one pass and spend their attention on the rest.
 *
 * What this must NOT become is a button that hides student compromises. Students get
 * phished too, their accounts are used to send internal mail that staff trust, and
 * "dismiss all" applied blind would bury exactly the case worth finding. So the bulk
 * action always shows what does NOT look like VPN noise first, and the operator dismisses
 * with that in front of them.
 */
const NOTABLE_SCORE = 90;
const NOTABLE_REASON = 'Sensitive Gmail action';
/** Reason text written by assessRisk for a sign-in outside the home countries. */
const NOTABLE_FOREIGN = 'OUTSIDE';
const notableOr = [
  { score: { gte: NOTABLE_SCORE } },
  { reasons: { contains: NOTABLE_REASON } },
  { reasons: { contains: NOTABLE_FOREIGN } }
];

const STATE_LABEL: Record<string, string> = {
  NEW: 'New',
  INVESTIGATING: 'Investigating',
  CONFIRMED_COMPROMISE: 'Confirmed',
  BENIGN: 'Benign',
  SUPPRESSED: 'Suppressed'
};

export default async function RiskPage({
  searchParams
}: {
  searchParams: Promise<{ state?: string; who?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { state = 'NEW', who = 'all' } = await searchParams;

  const settings = await getSettings(prisma);
  const staffSuffix = `@${settings.domains.staff}`;
  const studentSuffix = `@${settings.domains.students}`;

  const stateWhere = state === 'ALL' ? {} : { state: state as never };
  const audienceWhere =
    who === 'students'
      ? { mailbox: { endsWith: studentSuffix } }
      : who === 'staff'
        ? { mailbox: { endsWith: staffSuffix } }
        : {};
  const where = { ...stateWhere, ...audienceWhere };

  const studentWhere = { ...stateWhere, mailbox: { endsWith: studentSuffix } };

  const viewNotable = await prisma.wardenRiskFlag.findMany({
    where: { ...where, OR: notableOr },
    orderBy: { score: 'desc' },
    take: 12
  });

  const [flags, lastRun, baselineCount, matureCount, total, staffCount, studentCount, studentNotable] =
    await Promise.all([
      prisma.wardenRiskFlag.findMany({
        where,
        orderBy: [{ score: 'desc' }, { ts: 'desc' }],
        take: 200
      }),
      prisma.wardenScanRun.findFirst({ orderBy: { startedAt: 'desc' } }),
      prisma.wardenBaseline.count(),
      prisma.wardenBaseline.count({ where: { mature: true } }),
      prisma.wardenRiskFlag.count({ where }),
      prisma.wardenRiskFlag.count({ where: { ...stateWhere, mailbox: { endsWith: staffSuffix } } }),
      prisma.wardenRiskFlag.count({ where: studentWhere }),
      // Student flags that do NOT look like a teenager on a VPN. These are shown above the
      // bulk action so the "one look" is an informed look.
      prisma.wardenRiskFlag.findMany({
        where: {
          ...studentWhere,
          OR: notableOr
        },
        orderBy: { score: 'desc' },
        take: 12
      })
    ]);

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const id = String(formData.get('id'));
    const next = String(formData.get('state'));
    await prisma.wardenRiskFlag.update({
      where: { id },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `risk:${next}`, target: id }
    });
    revalidatePath('/risk');
  }

  /**
   * Investigate a flag: queue a read-only account check (filters, forwarding, delegates,
   * app passwords, OAuth scopes — the places a takeover hides) for that mailbox, mark the
   * flag as being looked at, and open the job. This is the "dig in" action the triage
   * buttons alone didn't give: a filter that silently forwards or deletes mail is the
   * single clearest sign an account was taken over, and it is exactly what the September
   * compromises left behind.
   */
  async function investigate(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const id = String(formData.get('id'));
    const flag = await prisma.wardenRiskFlag.findUnique({ where: { id } });
    if (!flag) redirect('/risk');
    const cfg = await getSettings(prisma);
    const domainKey = flag.mailbox.toLowerCase().endsWith(`@${cfg.domains.students.toLowerCase()}`) ? 'students' : 'staff';
    // Move it to Investigating so the queue shows it is being worked, unless it is already
    // a confirmed compromise (which this must never downgrade).
    if (flag.state === 'NEW') {
      await prisma.wardenRiskFlag.update({
        where: { id }, data: { state: 'INVESTIGATING', reviewedBy: u.email, reviewedAt: new Date() }
      }).catch(() => undefined);
    }
    const job = await prisma.wardenJob.create({
      data: {
        kind: 'ACCOUNT_CHECK', operatorId: u.id, domainKey,
        argsJson: JSON.stringify({ user: flag.mailbox }), query: flag.mailbox
      }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'account_check', target: flag.mailbox, detail: `from risk flag (score ${flag.score})` }
    }).catch(() => undefined);
    redirect(`/jobs/${job.id}`);
  }

  /**
   * Investigate everything in the current view at once: queue a read-only account check for
   * every DISTINCT mailbox shown (a mailbox with four flags gets one check, not four), mark
   * their NEW flags Investigating, and open the Jobs page to watch them run. Scoped to the
   * current state + audience tabs and recomputed here, never trusted from the form. Capped so
   * one click cannot queue hundreds of GAM scans; the riskiest mailboxes go first.
   */
  async function investigateAll(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const st = String(formData.get('state') ?? 'NEW');
    const w = String(formData.get('who') ?? 'all');
    const cfg = await getSettings(prisma);
    const stuSfx = `@${cfg.domains.students.toLowerCase()}`;
    const stateW = st === 'ALL' ? {} : { state: st as never };
    const audW =
      w === 'students' ? { mailbox: { endsWith: `@${cfg.domains.students}` } }
      : w === 'staff' ? { mailbox: { endsWith: `@${cfg.domains.staff}` } }
      : {};
    const viewFlags = await prisma.wardenRiskFlag.findMany({
      where: { ...stateW, ...audW },
      select: { mailbox: true, score: true }
    });
    const byMb = new Map<string, number>();
    for (const f of viewFlags) byMb.set(f.mailbox, Math.max(byMb.get(f.mailbox) ?? 0, f.score));
    const MAX = 50;
    const mailboxes = [...byMb.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX).map(([m]) => m);
    if (!mailboxes.length) redirect(`/risk?state=${st}&who=${w}`);

    await prisma.wardenRiskFlag.updateMany({
      where: { ...stateW, ...audW, state: 'NEW', mailbox: { in: mailboxes } },
      data: { state: 'INVESTIGATING', reviewedBy: u.email, reviewedAt: new Date() }
    });
    let firstJob = '';
    for (const mb of mailboxes) {
      const domainKey = mb.toLowerCase().endsWith(stuSfx) ? 'students' : 'staff';
      const job = await prisma.wardenJob.create({
        data: { kind: 'ACCOUNT_CHECK', operatorId: u.id, domainKey, argsJson: JSON.stringify({ user: mb }), query: mb }
      });
      if (!firstJob) firstJob = job.id;
    }
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'account_check_bulk', target: `${mailboxes.length} accounts`, detail: `risk view state=${st} who=${w}${byMb.size > MAX ? ` (capped from ${byMb.size})` : ''}` }
    }).catch(() => undefined);
    redirect('/jobs');
  }

  /**
   * Clear the student VPN noise in one pass.
   *
   * Scoped to exactly the rows the operator is looking at — the current state tab AND the
   * student domain — so it can never reach a staff flag, which is the failure that would
   * matter. The count is recomputed inside the action rather than trusted from the form,
   * because the form was rendered some seconds ago and a scan may have run since.
   *
   * The audit row records the count and how many of the dismissed flags were the notable
   * ones surfaced above the button, so a post-mortem can answer "did we wave past a real
   * student compromise" without re-deriving it.
   */
  async function dismissStudents(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect('/risk?who=students&error=role');

    const s = await getSettings(prisma);
    const scope = {
      ...(String(formData.get('state')) === 'ALL'
        ? {}
        : { state: String(formData.get('state')) as never }),
      mailbox: { endsWith: `@${s.domains.students}` }
    };

    const notable = await prisma.wardenRiskFlag.count({
      where: {
        ...scope,
        OR: notableOr
      }
    });
    const res = await prisma.wardenRiskFlag.updateMany({
      where: scope,
      data: { state: 'BENIGN' as never, reviewedBy: u.email, reviewedAt: new Date() }
    });

    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: 'risk:BENIGN:bulk-students',
        target: s.domains.students,
        resultCount: res.count,
        detail:
          `bulk-dismissed ${res.count} student sign-in flags as benign` +
          (notable
            ? ` — ${notable} of them scored ${NOTABLE_SCORE}+ or involved a sensitive Gmail action`
            : ' — none were high-scoring or involved a sensitive Gmail action')
      }
    });
    revalidatePath('/risk');
  }

  /**
   * Acknowledge everything in the current view as benign.
   *
   * For the day the queue is twenty VPN sign-ins and a conference out of state, and
   * clicking each one is how a queue stops being read. Restricted to the NEW and
   * INVESTIGATING tabs: a bulk action that could reach CONFIRMED_COMPROMISE would let one
   * click rewrite an incident record.
   *
   * Scoped to exactly the rows on screen — state AND audience — and recomputed in the
   * action, because the scan runs every few minutes. The audit row records how many were
   * notable (90+, sensitive Gmail action, or outside the home countries), so a post-mortem
   * can tell whether anyone waved past one.
   */
  async function acknowledgeAll(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect('/risk?error=role');

    const st = String(formData.get('state'));
    if (st !== 'NEW' && st !== 'INVESTIGATING') redirect('/risk');
    const w = String(formData.get('who') ?? 'all');
    const c = await getSettings(prisma);
    const scope = {
      state: st as never,
      ...(w === 'staff' ? { mailbox: { endsWith: `@${c.domains.staff}` } } : {}),
      ...(w === 'students' ? { mailbox: { endsWith: `@${c.domains.students}` } } : {})
    };

    const notable = await prisma.wardenRiskFlag.count({ where: { ...scope, OR: notableOr } });
    const res = await prisma.wardenRiskFlag.updateMany({
      where: scope,
      data: { state: 'BENIGN' as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: `risk:BENIGN:bulk-${w}`,
        target: w === 'all' ? 'all accounts' : w,
        resultCount: res.count,
        detail:
          `acknowledged ${res.count} ${st} sign-in flag${res.count === 1 ? '' : 's'} as benign (${w})` +
          (notable
            ? ` — ${notable} were notable (90+, sensitive Gmail action, or outside the home country)`
            : ' — none notable')
      }
    });
    revalidatePath('/risk');
  }

  const stale =
    lastRun?.startedAt && Date.now() - lastRun.startedAt.getTime() > 8 * 3600_000;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Sign-in risk</h1>
          <p className="text-sm text-text-muted">
            Scored against each mailbox&rsquo;s own learned normal, not a fixed threshold.
            {total > flags.length && (
              <>
                {' '}
                Showing the {flags.length} highest-scoring of <strong>{total}</strong> in this
                view.
              </>
            )}
          </p>
        </div>
        <div className="text-right text-xs text-text-muted">
          <div>
            {baselineCount} baselines &middot;{' '}
            <span className={matureCount < baselineCount ? 'text-warning' : ''}>
              {matureCount} mature
            </span>
          </div>
          {lastRun ? (
            /*
              Coloured on the OUTCOME, not on staleness. A scan that failed ten minutes ago
              used to render in ordinary grey while the table below said "Nothing flagged",
              and the screen read "all clear".

              The coverage numbers matter as much as the timestamp: a wrong staff domain, a
              rotated GAM credential that exits 0, or an empty report all give eventsSeen: 0
              with ok: true and a fresh time. "0 events" and "a quiet district" must not
              look the same.
            */
            <div
              className={
                lastRun.finishedAt === null ? '' : !lastRun.ok ? 'text-danger' : stale ? 'text-warning' : ''
              }
            >
              <div>
                last scan {fmtTs(lastRun.startedAt)}
                {lastRun.finishedAt === null
                  ? ' — running now'
                  : lastRun.ok
                    ? ''
                    : ' — FAILED'}
                {lastRun.finishedAt !== null && lastRun.ok && stale ? ' — overdue' : ''}
              </div>
              {lastRun.finishedAt !== null && (
                <div className={lastRun.eventsSeen === 0 ? 'text-warning' : ''}>
                  {lastRun.eventsSeen.toLocaleString()} events seen
                  {lastRun.eventsSeen === 0 && ' — saw nothing, check the domain and GAM auth'}
                  {lastRun.eventsSeen > 0 && ` · ${lastRun.flagsRaised} flagged`}
                </div>
              )}
            </div>
          ) : (
            <div className="text-warning">no scan has run yet</div>
          )}
        </div>
      </header>

      {baselineCount > 0 && matureCount < baselineCount * 0.5 && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--warning) / 0.4)' }}>
          <strong className="text-warning">Baselines still learning.</strong>{' '}
          Fewer than half of mailboxes have enough history to score confidently. Until
          then scores are damped and some genuine anomalies will read low. Expect this to
          settle after a few days of scans.
        </div>
      )}

      <div className="flex flex-wrap gap-1.5 text-xs">
        {['NEW', 'INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN', 'ALL'].map((s) => (
          <a
            key={s}
            href={`/risk?state=${s}&who=${who}`}
            className={`rounded border px-2.5 py-1 ${
              s === state ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
            }`}
          >
            {s === 'ALL' ? 'All' : STATE_LABEL[s]}
          </a>
        ))}
      </div>

      {/*
        Staff and students are different problems. A student flag is usually a teenager on
        a VPN and there are a lot of them; a staff flag is how a district gets compromised.
        Splitting them lets the noise be cleared in one pass instead of being scrolled past
        every day until the whole queue is ignored.
      */}
      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        <span className="text-text-muted">Accounts:</span>
        {[
          ['all', 'Everyone', staffCount + studentCount],
          ['staff', 'Staff', staffCount],
          ['students', 'Students', studentCount]
        ].map(([key, label, n]) => (
          <a
            key={key as string}
            href={`/risk?state=${state}&who=${key}`}
            className={`rounded border px-2.5 py-1 ${
              key === who ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
            }`}
          >
            {label as string} <span className="text-text-muted">({n as number})</span>
          </a>
        ))}
      </div>

      {/*
        An empty Students tab has two very different causes and they must not look alike:
        nothing flagged, or nothing ever scanned. Warden shipped scanning the staff domain
        only, so this read "Students (0)" over 6,336 mailboxes with no coverage at all.
      */}
      {who === 'students' && studentCount === 0 && !settings.scanStudentSignIns && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--warning) / 0.5)' }}>
          <strong className="text-warning">Student sign-ins are not being scored.</strong>
          <p className="mt-1 text-text-muted">
            This is zero because nothing has been scanned, not because nothing was found.
            Turn on <span className="mono">Score student sign-ins too</span> in{' '}
            <a href="/settings?tab=Sign-in+risk" className="underline">
              Settings &rarr; Sign-in risk
            </a>
            . The GAM login report is tenant-wide, so these events are already being fetched
            and discarded &mdash; enabling it costs no extra API calls. Expect a noisy queue;
            the bulk dismiss below is built for exactly that.
          </p>
        </div>
      )}

      {who !== 'students' &&
        (state === 'NEW' || state === 'INVESTIGATING') &&
        total > 0 &&
        user.role !== 'ANALYST' && (
          <div className="card space-y-3">
            <div className="text-sm font-medium">
              Acknowledge all {total} {who === 'staff' ? 'staff ' : ''}flag{total === 1 ? '' : 's'} in
              this view as benign
            </div>

            {viewNotable.length > 0 ? (
              <div className="rounded border p-3 text-sm" style={{ borderColor: 'rgb(var(--warning) / 0.5)' }}>
                <strong className="text-warning">Look at {viewNotable.length} of these first.</strong>{' '}
                They scored {NOTABLE_SCORE}+, involved a sensitive Gmail action such as creating a
                filter, or came from outside the home country. Those are what takeovers looked like
                in September &mdash; acknowledging all will close them too.
                <ul className="mt-2 space-y-1">
                  {viewNotable.map((f) => {
                    const why = (JSON.parse(f.reasons) as string[]).find((r) =>
                      /OUTSIDE|Sensitive Gmail action|suspicious/i.test(r)
                    );
                    return (
                      <li key={f.id} className="mono text-xs">
                        <span className={`pill pill-${band(f.score)}`}>{f.score}</span> {f.mailbox} &middot;{' '}
                        {fmtTs(f.ts)}
                        {why ? <span className="text-text-muted"> &middot; {why}</span> : null}
                      </li>
                    );
                  })}
                </ul>
                <p className="mt-2 text-xs text-text-muted">
                  To keep one open, set it to Investigating first &mdash; or run this from the
                  Investigating tab only once you have cleared those.
                </p>
              </div>
            ) : (
              <p className="text-sm text-text-muted">
                None of these scored {NOTABLE_SCORE}+, touched mail settings, or came from outside
                the home country.
              </p>
            )}

            <form action={acknowledgeAll}>
              <input type="hidden" name="state" value={state} />
              <input type="hidden" name="who" value={who} />
              <PendingButton pending="Acknowledging…">
                Acknowledge all {total} as benign
              </PendingButton>
            </form>
            <p className="text-xs text-text-muted">
              Acts on exactly this view &mdash; the {state === 'NEW' ? 'New' : 'Investigating'} tab
              {who === 'staff' ? ', staff accounts only' : ', all accounts'} &mdash; including any not shown
              on this page. Confirmed compromises are never touched. Reversible: they move to Benign,
              and the audit log records the count and your name.
            </p>
          </div>
        )}

      {who === 'students' && studentCount > 0 && user.role !== 'ANALYST' && (
        <div className="card space-y-3">
          <div className="text-sm font-medium">
            Clear {studentCount} student flag{studentCount === 1 ? '' : 's'} in one pass
          </div>

          {studentNotable.length > 0 ? (
            <>
              <div
                className="rounded border p-3 text-sm"
                style={{ borderColor: 'rgb(var(--warning) / 0.5)' }}
              >
                <strong className="text-warning">
                  Look at {studentNotable.length} of these first.
                </strong>{' '}
                They scored {NOTABLE_SCORE}+ or involved a sensitive Gmail action such as
                filter creation. That is not what a VPN looks like &mdash; it is what a taken-over
                account looks like, and students get phished too. Their accounts are trusted
                by staff precisely because they are internal.
                <ul className="mt-2 space-y-1">
                  {studentNotable.map((f) => (
                    <li key={f.id} className="mono text-xs">
                      <span className={`pill pill-${band(f.score)}`}>{f.score}</span>{' '}
                      {f.mailbox} &middot; {fmtTs(f.ts)}
                      {f.ip ? ` · ${f.ip}` : ''}
                    </li>
                  ))}
                </ul>
              </div>
              <p className="text-xs text-text-muted">
                Dismissing now marks those {studentNotable.length} benign too. If you want to
                keep them, set them to Investigating first &mdash; they will then be out of the
                NEW tab and the bulk action will not reach them.
              </p>
            </>
          ) : (
            <p className="text-sm text-text-muted">
              None of these scored {NOTABLE_SCORE}+ and none involved a sensitive Gmail
              action. This looks like ordinary VPN noise.
            </p>
          )}

          <form action={dismissStudents}>
            <input type="hidden" name="state" value={state} />
            <button className="btn text-xs">
              Mark all {studentCount} student flag{studentCount === 1 ? '' : 's'} benign
            </button>
          </form>
          <p className="text-xs text-text-muted">
            Reversible &mdash; they move to the Benign tab, nothing is deleted, and the audit log
            records the count and your name. Staff flags are never touched by this button.
          </p>
        </div>
      )}

      {flags.length === 0 ? (
        <div className="card text-sm text-text-muted">
          Nothing flagged in this view.
          {lastRun && !lastRun.ok && (
            <>
              {' '}
              <strong className="text-warning">
                The last scan FAILED, so this may mean the scan did not run rather than that
                there is nothing to find.
              </strong>
            </>
          )}
        </div>
      ) : (
        <>
        {(() => {
          const accounts = new Set(flags.map((f) => f.mailbox)).size;
          return (
            <form action={investigateAll} className="mb-2 flex flex-wrap items-center gap-2">
              <input type="hidden" name="state" value={state} />
              <input type="hidden" name="who" value={who} />
              <PendingButton className="btn btn-primary text-xs" pending="Queuing…">
                Investigate all {accounts} account{accounts === 1 ? '' : 's'} in this view
              </PendingButton>
              <span className="text-xs text-text-muted">
                Queues a read-only account check per mailbox (deduplicated) and marks them Investigating.
                {accounts > 50 && ' Capped at the 50 highest-scoring.'}
              </span>
            </form>
          );
        })()}
        <div className="overflow-x-auto rounded border">
          <table className="w-full border-collapse bg-bg-surface">
            <thead className="border-b bg-bg-elevated">
              <tr>
                <th className="th w-16">Score</th>
                <th className="th">Mailbox</th>
                <th className="th w-40">When</th>
                <th className="th">Why</th>
                <th className="th w-48">Network</th>
                <th className="th w-56">Triage</th>
              </tr>
            </thead>
            <tbody>
              {flags.map((f) => {
                const reasons: string[] = JSON.parse(f.reasons);
                const b = band(f.score);
                return (
                  <tr key={f.id} className="border-b last:border-0 align-top">
                    <td className="td">
                      <span className={`pill pill-${b === 'low' ? 'muted' : b}`}>{f.score}</span>
                    </td>
                    <td className="td mono">{f.mailbox.split('@')[0]}</td>
                    <td className="td mono text-text-muted">
                      {fmtTs(f.ts)}
                    </td>
                    <td className="td">
                      <ul className="space-y-0.5">
                        {reasons.map((r, i) => (
                          <li key={i} className="text-text-muted">
                            &bull; {r}
                          </li>
                        ))}
                      </ul>
                    </td>
                    <td className="td mono text-text-muted">
                      {f.ip ?? '—'}
                      <br />
                      {f.asn ? `AS${f.asn}` : ''} {f.geo ?? ''}
                    </td>
                    <td className="td">
                      <form action={investigate} className="mb-1">
                        <input type="hidden" name="id" value={f.id} />
                        <PendingButton className="btn btn-primary px-2 py-1 text-xs" pending="Starting…">
                          Investigate
                        </PendingButton>
                      </form>
                      <div className="flex flex-wrap gap-1">
                        {(['INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN'] as const).map((s) => (
                          <form key={s} action={setState}>
                            <input type="hidden" name="id" value={f.id} />
                            <input type="hidden" name="state" value={s} />
                            <button
                              className={`btn px-2 py-1 text-xs ${
                                s === 'CONFIRMED_COMPROMISE' ? 'btn-verdict' : ''
                              }`}
                              disabled={f.state === s}
                            >
                              {STATE_LABEL[s]}
                            </button>
                          </form>
                        ))}
                      </div>
                      <div className="mt-1 text-xs text-text-muted">
                        <a href={`/accounts?user=${encodeURIComponent(f.mailbox)}`} className="underline">account</a>
                        {f.reviewedBy && <> &middot; {STATE_LABEL[f.state]} &middot; {f.reviewedBy.split('@')[0]}</>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        </>
      )}

      <p className="text-xs text-text-muted">
        This scan never suspends or resets anyone. During the September incidents two of
        the three most alarming sign-ins were carrier geolocation artefacts — AT&amp;T
        Mobility IPv6 geolocates to Texas wherever the handset is. Confirm with the user
        before acting.
      </p>
    </div>
  );
}
