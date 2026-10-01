import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { campaignKey } from '@/lib/reports';
import { getSettings } from '@/lib/settings';
import { freshnessFor } from '@/lib/freshness';
import { IngestStatus, EmptyQueue } from '@/components/IngestStatus';
import Link from 'next/link';
import { Inbox } from 'lucide-react';

export const dynamic = 'force-dynamic';

const STATES = ['NEW', 'TRIAGED', 'CONFIRMED_PHISH', 'SPAM', 'KNOWN_GOOD', 'BENIGN', 'ALL'] as const;

const SORTS = [
  { key: 'recent', label: 'Newest first' },
  { key: 'oldest', label: 'Oldest first' },
  { key: 'count', label: 'Most reported' }
] as const;

/** Hard ceiling on rows pulled into one page. Shown to the operator when it bites. */
const PAGE_LIMIT = 1000;

export default async function ReportsPage({
  searchParams
}: {
  searchParams: Promise<{ state?: string; sort?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { state = 'NEW', sort = 'recent' } = await searchParams;
  const where = state === 'ALL' ? {} : { state: state as never };

  const cfg = await getSettings(prisma);
  const fresh = await freshnessFor(prisma, 'reports', cfg.schedule.reportsMinutes);

  const [matching, reports] = await Promise.all([
    prisma.wardenReport.count({ where }),
    prisma.wardenReport.findMany({
      where,
      orderBy: { reportedAt: sort === 'oldest' ? 'asc' : 'desc' },
      take: PAGE_LIMIT
    })
  ]);

  /**
   * Group by campaign so 61 reports of one thing read as one problem, not 61.
   *
   * Uses `campaignKey()` from src/lib/reports.ts — the function written for exactly this
   * and, until now, imported by no page. The local version this replaces keyed on a
   * 60-character subject prefix with `re:`/`fwd:` stripped, which is wrong here in two
   * specific ways:
   *
   *   - It ignored the payload host. This attacker rotates senders every day or two
   *     against a FIXED payload — nine accounts behind one downloaddocument.tech — so one
   *     campaign fragmented into nine, each triaged and scoped separately.
   *   - It did not strip gateway tags. The day a new content rule switches on, tagged
   *     copies stop matching untagged ones, one campaign silently becomes two, and the
   *     count on this page halves.
   *
   * Both were already documented in reports.ts. The page just wasn't calling it.
   */
  const groups = new Map<string, typeof reports>();
  for (const r of reports) {
    const key = campaignKey({
      payloadHosts: JSON.parse(r.payloadHosts ?? '[]') as string[],
      originalSubject: r.originalSubject,
      originalSender: r.originalSender
    } as never);
    groups.set(key, [...(groups.get(key) ?? []), r]);
  }

  // Compute each group's span explicitly rather than trusting array order — the order
  // flips with the sort, and reading rs[0] as "newest" silently inverts every date range.
  //
  // `key` is a truncated, normalised grouping token. It is NOT the label: showing it cut
  // subjects off mid-word ("...Item shared with you: \"DistrictPayrollRegul"), which hides
  // the very part that distinguishes one campaign from another.
  const spans = [...groups.entries()].map(([key, rs]) => {
    const times = rs.map((r) => r.reportedAt.getTime());
    const label =
      rs.map((r) => r.originalSubject).find((s) => s && s.length) ??
      rs.map((r) => r.originalSender).find(Boolean) ??
      'unparsed report';
    return {
      key,
      label,
      rs,
      first: new Date(Math.min(...times)),
      last: new Date(Math.max(...times))
    };
  });

  spans.sort((a, b) => {
    if (sort === 'count') return b.rs.length - a.rs.length;
    if (sort === 'oldest') return a.first.getTime() - b.first.getTime();
    return b.last.getTime() - a.last.getTime();
  });

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const key = String(formData.get('key'));
    const next = String(formData.get('state'));
    const ids = String(formData.get('ids')).split(',').filter(Boolean);
    await prisma.wardenReport.updateMany({
      where: { id: { in: ids } },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });

    // A report and its Alert Center twin are one event. Without this the alert queue keeps
    // asking about something that has already been decided, which is how 107 alerts sat
    // NEW while their reports were triaged.
    const touched = await prisma.wardenReport.findMany({
      where: { id: { in: ids }, alertId: { not: null } },
      select: { alertId: true }
    });
    if (touched.length) {
      await prisma.wardenAlert.updateMany({
        where: { alertId: { in: touched.map((t) => t.alertId!) } },
        data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
      });
    }

    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `report:${next}`, target: key, resultCount: ids.length }
    });
    revalidatePath('/reports');
    revalidatePath('/alerts');
  }

  const day = (d: Date) => d.toISOString().slice(0, 10);

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Reports</h1>
        <p className="text-sm text-text-muted">
          What staff flagged with the Phish Alert Button, grouped by campaign.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex flex-wrap gap-1.5 text-xs">
          {STATES.map((s) => (
            <a
              key={s}
              href={`/reports?state=${s}&sort=${sort}`}
              className={`rounded border px-2.5 py-1 ${
                s === state ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
              }`}
            >
              {s === 'ALL' ? 'All' : s.replace('_', ' ')}
            </a>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-text-muted">Sort</span>
          {SORTS.map((s) => (
            <a
              key={s.key}
              href={`/reports?state=${state}&sort=${s.key}`}
              className={`rounded border px-2.5 py-1 ${
                s.key === sort ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
              }`}
            >
              {s.label}
            </a>
          ))}
        </div>
      </div>

      {reports.length > 0 && (
        <p className="text-xs text-text-muted">
          {matching.toLocaleString()} report{matching === 1 ? '' : 's'} in this view,
          grouped into {spans.length} campaign{spans.length === 1 ? '' : 's'}.
          {matching > PAGE_LIMIT && (
            <>
              {' '}
              <strong>Showing the first {PAGE_LIMIT.toLocaleString()}</strong> by this sort —{' '}
              {(matching - PAGE_LIMIT).toLocaleString()} not displayed.
            </>
          )}
        </p>
      )}

      <IngestStatus f={fresh} what="report" />

      {reports.length === 0 ? (
        <EmptyQueue f={fresh} what="report" />
      ) : (
        <div className="space-y-3">
          {spans.map(({ key, label, rs, first, last }) => {
            const hosts = [
              ...new Set(rs.flatMap((r) => JSON.parse(r.payloadHosts ?? '[]') as string[]))
            ];
            const senders = [...new Set(rs.map((r) => r.originalSender).filter(Boolean))];
            const reporters = [...new Set(rs.map((r) => r.reporter))];
            const ids = rs.map((r) => r.id).join(',');
            const days = Math.round((last.getTime() - first.getTime()) / 86_400_000);
            return (
              <div key={key} className="card space-y-2">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <Link href={`/reports/${rs[0].id}`} className="font-medium underline-offset-2 hover:underline">{label}</Link>
                    <div className="mt-0.5 text-xs text-text-muted">
                      {rs.length} report{rs.length === 1 ? '' : 's'} from {reporters.length}{' '}
                      {reporters.length === 1 ? 'person' : 'people'} &middot;{' '}
                      {days === 0 ? day(last) : `${day(first)} → ${day(last)} (${days}d)`}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {(['CONFIRMED_PHISH', 'SPAM', 'BENIGN', 'KNOWN_GOOD'] as const).map((st) => (
                      <form key={st} action={setState}>
                        <input type="hidden" name="key" value={key} />
                        <input type="hidden" name="ids" value={ids} />
                        <input type="hidden" name="state" value={st} />
                        <button
                          className={`btn px-2 py-1 text-xs ${st === 'CONFIRMED_PHISH' ? 'btn-verdict' : ''}`}
                        >
                          {st.replace('_', ' ').toLowerCase()}
                        </button>
                      </form>
                    ))}
                  </div>
                </div>

                {senders.length > 0 && (
                  <div className="text-xs">
                    <span className="text-text-muted">sender: </span>
                    <span className="mono">{senders.slice(0, 4).join(', ')}</span>
                    {senders.length > 4 && (
                      <span className="text-text-muted"> +{senders.length - 4} more</span>
                    )}
                  </div>
                )}
                {hosts.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="text-text-muted">payload:</span>
                    {hosts.slice(0, 6).map((h) => (
                      <span key={h} className="pill pill-critical mono">
                        {h}
                      </span>
                    ))}
                  </div>
                )}

                <details className="text-xs">
                  <summary className="cursor-pointer text-text-muted">
                    individual reports ({rs.length})
                  </summary>
                  <table className="mt-2 w-full border-collapse">
                    <thead className="border-b">
                      <tr>
                        <th className="th w-28">Reported</th>
                        <th className="th">Reporter</th>
                        <th className="th w-32">State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...rs]
                        .sort((a, b) =>
                          sort === 'oldest'
                            ? a.reportedAt.getTime() - b.reportedAt.getTime()
                            : b.reportedAt.getTime() - a.reportedAt.getTime()
                        )
                        .map((r) => (
                          <tr key={r.id} className="border-b last:border-0">
                            <td className="td mono">
                              {r.reportedAt.toISOString().slice(0, 16).replace('T', ' ')}
                            </td>
                            <td className="td"><Link href={`/reports/${r.id}`} className="mono underline-offset-2 hover:underline">{r.reporter}</Link></td>
                            <td className="td">
                              <span className="pill pill-muted">{r.state.replace('_', ' ')}</span>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </details>

                {rs[0].notes && <div className="text-xs text-text-muted">{rs[0].notes}</div>}
              </div>
            );
          })}
        </div>
      )}

      <p className="text-xs text-text-muted">
        A report is a person saying &ldquo;this looks wrong&rdquo; &mdash; not a confirmed
        finding. Between March and September 2026, 504 reports from 190 staff went to a
        decommissioned PhishER tenant. The detection worked; nothing was reading it.
      </p>
    </div>
  );
}
