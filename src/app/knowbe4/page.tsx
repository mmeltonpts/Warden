import { redirect } from 'next/navigation';
import { fmtDate } from '@/lib/time';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { GraduationCap, TriangleAlert, ShieldCheck, Users2 } from 'lucide-react';

export const dynamic = 'force-dynamic';

function pct(n: number | null | undefined) {
  return n === null || n === undefined ? '—' : `${n.toFixed(1)}%`;
}
function day(d: Date | null | undefined) {
  return d ? fmtDate(d) : 'never';
}

export default async function KnowBe4Page() {
  const user = await currentUser();
  if (!user) redirect('/login');

  const account = await prisma.wardenKb4Account.findUnique({ where: { id: 1 } });
  if (!account) {
    return (
      <div className="card flex items-start gap-2 text-sm text-text-muted">
        <GraduationCap size={16} className="mt-0.5 shrink-0" />
        <div>
          No KnowBe4 data yet. Run <code className="mono">npx tsx scripts/sync-knowbe4.ts</code> on
          the server, or enable KnowBe4 in Settings if it is off.
          {account === null && <span className="sr-only">no account row</span>}
        </div>
      </div>
    );
  }

  const admins = JSON.parse(account.admins || '[]') as Array<{ name: string; email: string }>;

  const [total, active, neverSignedIn, highPpp, unmanaged] = await Promise.all([
    prisma.wardenKb4User.count(),
    prisma.wardenKb4User.count({ where: { status: 'active' } }),
    prisma.wardenKb4User.count({ where: { lastSignIn: null } }),
    prisma.wardenKb4User.count({ where: { phishPronePct: { gte: 40 } } }),
    prisma.wardenKb4User.count({ where: { provisioningManaged: false } })
  ]);

  // ── the join that justifies this page existing ────────────────────────────
  // Warden flagged these mailboxes on real sign-in behaviour. KnowBe4 has an opinion about
  // the same people. Neither view is worth much alone; together they rank a queue.
  const openFlags = await prisma.wardenRiskFlag.findMany({
    where: { state: { in: ['NEW', 'INVESTIGATING'] } },
    orderBy: { score: 'desc' },
    take: 40,
    select: { mailbox: true, score: true, ts: true, reasons: true, geo: true }
  });
  const flagged = await prisma.wardenKb4User.findMany({
    where: { email: { in: openFlags.map((f) => f.mailbox.toLowerCase()) } }
  });
  const kb4By = new Map(flagged.map((u) => [u.email, u]));

  /**
   * Ordered by the WARDEN score, not by phish-prone.
   *
   * It used to sort on `phishPronePct ?? -1`, which pushed anyone absent from the KSAT
   * roster to the bottom — and the table is then sliced to 15. So a Warden-95 flag for
   * someone not in KSAT was cut from the table entirely, by the very number the paragraph
   * underneath calls "a prior, not evidence" that "does not decide anything". Deciding
   * what an analyst can see is a stronger power than ordering, not a weaker one.
   *
   * Sign-in evidence ranks. The training prior is a column.
   */
  const correlated = openFlags
    .map((f) => ({ flag: f, kb4: kb4By.get(f.mailbox.toLowerCase()) }))
    .sort((a, b) => b.flag.score - a.flag.score);
  const missingFromKsat = correlated.filter((c) => !c.kb4).length;

  // ── who actually reports phish ────────────────────────────────────────────
  const reporters = await prisma.wardenReport.groupBy({
    by: ['reporter'],
    _count: { _all: true },
    orderBy: { _count: { reporter: 'desc' } },
    take: 15
  });
  const reporterKb4 = await prisma.wardenKb4User.findMany({
    where: { email: { in: reporters.map((r) => r.reporter.toLowerCase()) } }
  });
  const repBy = new Map(reporterKb4.map((u) => [u.email, u]));

  const topPpp = await prisma.wardenKb4User.findMany({
    where: { phishPronePct: { gt: 0 }, status: 'active' },
    orderBy: { phishPronePct: 'desc' },
    take: 12
  });

  const overSeats = account.seats ? total - account.seats : 0;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-lg font-semibold">KnowBe4</h1>
        <p className="text-sm text-text-muted">
          Mirrored from KSAT {day(account.syncedAt)}. KSAT is the system of record; this is a
          cache, kept locally so it can be joined against Warden&rsquo;s own data.
        </p>
      </header>

      {account.lastError && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.4)' }}>
          Last sync failed: <span className="mono">{account.lastError}</span>
        </div>
      )}

      {/* ── account ──────────────────────────────────────────────────────── */}
      <div className="card space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <div className="font-medium">{account.name}</div>
          <div className="text-xs text-text-muted">
            {account.subscriptionLevel ?? 'unknown tier'}
            {account.subscriptionEnds && ` · renews ${day(account.subscriptionEnds)}`}
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-4">
          {[
            { label: 'Account risk score', value: account.riskScore?.toFixed(1) ?? '—' },
            { label: 'Licensed seats', value: account.seats?.toLocaleString() ?? '—' },
            { label: 'Users in roster', value: total.toLocaleString() },
            { label: 'Phish-prone ≥ 40%', value: highPpp.toLocaleString() }
          ].map((s) => (
            <div key={s.label}>
              <div className="text-xl font-semibold">{s.value}</div>
              <div className="text-xs text-text-muted">{s.label}</div>
            </div>
          ))}
        </div>
        {admins.length > 0 && (
          <div className="text-xs text-text-muted">
            KSAT admins: {admins.map((a) => a.name).join(', ')}
          </div>
        )}
      </div>

      {/* ── hygiene ──────────────────────────────────────────────────────── */}
      <div className="card space-y-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <TriangleAlert size={15} style={{ color: 'rgb(var(--warning))' }} /> Roster hygiene
        </div>
        <table className="w-full border-collapse text-sm">
          <tbody>
            {[
              overSeats > 0 && {
                k: `${overSeats.toLocaleString()} users beyond the licensed seat count`,
                v: `${total.toLocaleString()} in roster vs ${account.seats?.toLocaleString()} seats — usually departed staff still present`
              },
              {
                k: `${neverSignedIn.toLocaleString()} have never signed in to KSAT`,
                v: 'Enrolled but never engaged. Their training state is nominal, not real.'
              },
              {
                k: `${(total - active).toLocaleString()} are not in "active" status`,
                v: `${active.toLocaleString()} active of ${total.toLocaleString()}.`
              },
              unmanaged > 0 && {
                k: `${unmanaged.toLocaleString()} are not provisioning-managed`,
                v: 'Created by hand rather than by directory sync, so they will not be removed automatically.'
              }
            ]
              .filter(Boolean)
              .map((r) => (
                <tr key={(r as { k: string }).k} className="border-b last:border-0">
                  <td className="td font-medium">{(r as { k: string }).k}</td>
                  <td className="td text-text-muted">{(r as { v: string }).v}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {/* ── the correlation ──────────────────────────────────────────────── */}
      <div className="card space-y-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <ShieldCheck size={15} style={{ color: 'rgb(var(--info))' }} /> Open risk flags, with
          their KnowBe4 record
        </div>
        <p className="text-xs text-text-muted">
          Warden flagged these on real sign-in behaviour, and that score is what orders this
          table. The KnowBe4 columns are context for the phone call, not evidence, and they
          do not affect the ranking or the score.
          {missingFromKsat > 0 && (
            <>
              {' '}
              <strong className="text-text-primary">
                {missingFromKsat} of these {correlated.length} are not in the KSAT roster
              </strong>{' '}
              &mdash; shown with blank KnowBe4 columns rather than dropped. Absence from a
              training roster is not evidence of anything, and it used to push them off the
              bottom of this list.
            </>
          )}
        </p>
        {correlated.length === 0 ? (
          <div className="text-sm text-text-muted">No open risk flags.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead className="border-b">
                <tr>
                  <th className="th">Mailbox</th>
                  <th className="th w-20">Warden</th>
                  <th className="th w-24">Phish-prone</th>
                  <th className="th w-24">KB4 risk</th>
                  <th className="th">Where they work</th>
                </tr>
              </thead>
              <tbody>
                {correlated.slice(0, 25).map(({ flag, kb4 }) => (
                  <tr key={flag.mailbox + flag.ts.toISOString()} className="border-b last:border-0">
                    <td className="td">
                      <div className="mono">{flag.mailbox}</div>
                      <div className="text-xs text-text-muted">
                        {day(flag.ts)} {flag.geo ? `· ${flag.geo}` : ''}
                      </div>
                    </td>
                    <td className="td">
                      <span className={`pill ${flag.score >= 70 ? 'pill-critical' : 'pill-high'}`}>
                        {flag.score}
                      </span>
                    </td>
                    <td className="td mono">{kb4 ? pct(kb4.phishPronePct) : 'not in KSAT'}</td>
                    <td className="td mono">{kb4?.riskScore?.toFixed(1) ?? '—'}</td>
                    <td className="td text-xs text-text-muted">
                      {kb4 ? [kb4.jobTitle, kb4.location].filter(Boolean).join(' · ') || '—' : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── reporters ────────────────────────────────────────────────────── */}
      <div className="card space-y-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Users2 size={15} style={{ color: 'rgb(var(--success))' }} /> Who reports phishing
        </div>
        <p className="text-xs text-text-muted">
          These people caught something and told someone. Between March and September 2026, 504
          such reports went to a decommissioned tenant and nobody read them &mdash; the
          detection was never the weak link.
        </p>
        {reporters.length === 0 ? (
          <div className="text-sm text-text-muted">
            No reports ingested yet. Run <code className="mono">scripts/ingest-reports.ts</code>.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead className="border-b">
                <tr>
                  <th className="th">Reporter</th>
                  <th className="th w-24">Reports</th>
                  <th className="th w-28">Phish-prone</th>
                  <th className="th">Building</th>
                </tr>
              </thead>
              <tbody>
                {reporters.map((r) => {
                  const k = repBy.get(r.reporter.toLowerCase());
                  return (
                    <tr key={r.reporter} className="border-b last:border-0">
                      <td className="td mono">{r.reporter}</td>
                      <td className="td">{r._count._all}</td>
                      <td className="td mono">{k ? pct(k.phishPronePct) : '—'}</td>
                      <td className="td text-xs text-text-muted">{k?.location ?? '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── phish-prone, with its caveat attached ────────────────────────── */}
      <div className="card space-y-2">
        <div className="text-sm font-medium">Highest phish-prone percentage</div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead className="border-b">
              <tr>
                <th className="th">User</th>
                <th className="th w-24">Phish-prone</th>
                <th className="th w-24">KB4 risk</th>
                <th className="th">Department</th>
              </tr>
            </thead>
            <tbody>
              {topPpp.map((u) => (
                <tr key={u.kb4Id} className="border-b last:border-0">
                  <td className="td mono">{u.email}</td>
                  <td className="td mono">{pct(u.phishPronePct)}</td>
                  <td className="td mono">{u.riskScore?.toFixed(1) ?? '—'}</td>
                  <td className="td text-xs text-text-muted">{u.department || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-text-muted">
          A phish-prone percentage is a prior, not evidence: it says someone is likelier to fall
          for something, not that they did.{' '}
          <strong className="text-text-primary">
            It does not feed the Warden risk score at all.
          </strong>{' '}
          Nothing on this page changes a single point of any sign-in score &mdash; these columns
          order a queue and tell you who to call first, and that is the whole of it. If you
          are weighing a flagged sign-in, weigh it on its own evidence and treat this as
          background. All four accounts compromised between
          8 and 13 September had two-step verification enrolled <em>and</em> enforced, and the
          attacker defeated it by real-time relay &mdash; no training metric predicted any of
          them. Values above 100% are possible and mean a user failed more interaction types
          than tests sent. This list is for targeting support, not for ranking staff.
        </p>
      </div>
    </div>
  );
}
