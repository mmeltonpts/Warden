import { redirect } from 'next/navigation';
import { fmtTs } from '@/lib/time';
import { revalidatePath } from 'next/cache';
import Link from 'next/link';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { freshnessFor } from '@/lib/freshness';
import { IngestStatus } from '@/components/IngestStatus';
import { ShieldBan } from 'lucide-react';

export const dynamic = 'force-dynamic';

/**
 * Admin quarantine, read from the Gmail delivery log.
 *
 * Quarantined mail never reaches a mailbox, so every scope is blind to it. A
 * superintendent-impersonation ACH request aimed at accounts payable was held here and was
 * invisible to the rest of the console.
 *
 * This page cannot release or deny — Google has no API for either. It records what was
 * held, which rule held it, whether it matches a known indicator, and who has reviewed it.
 */
export default async function QuarantinePage({
  searchParams
}: {
  searchParams: Promise<{ view?: string; rule?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  // ADMIN only, deliberately. Quarantine holds mail that was never delivered to anyone —
  // including the superintendent's own correspondence and regulatory threads that a
  // content rule caught by mistake. Nobody below ADMIN sees it, its counts, or its digest.
  if (user.role !== 'ADMIN') {
    return <div className="card text-sm">Quarantine requires the ADMIN role.</div>;
  }
  const { view = 'open', rule } = await searchParams;

  const s = await getSettings(prisma);
  const fresh = await freshnessFor(prisma, 'quarantine', s.schedule.quarantineMinutes ?? 10);

  /**
   * History. Marking a row used to drop it out of the default view with no obvious way
   * back — the only route was an 'Everything' tab mixing it with all else. Denied and
   * Released are tabs of their own, newest decision first, with who and when on each row.
   */
  const viewWhere =
    view === 'open' ? { reviewedBy: null }
    : view === 'denied' ? { notes: 'denied' }
    : view === 'released' ? { notes: 'released' }
    : view === 'reviewed' ? { reviewedBy: { not: null } }
    : view === 'ioc' ? { iocHit: { not: null } }
    : {};

  const where = {
    ...viewWhere,
    ...(rule ? { ruleName: rule } : {})
  };

  const [rows, total, byRule, iocCount, openCount, deniedCount, releasedCount, reviewedCount] = await Promise.all([
    prisma.wardenQuarantine.findMany({
      where,
      orderBy: view === 'denied' || view === 'released' || view === 'reviewed' ? { reviewedAt: 'desc' } : { heldAt: 'desc' },
      take: 300
    }),
    prisma.wardenQuarantine.count({ where }),
    prisma.wardenQuarantine.groupBy({
      by: ['ruleName'],
      where: viewWhere,
      _count: { _all: true }
    }),
    prisma.wardenQuarantine.count({ where: { iocHit: { not: null }, reviewedBy: null } }),
    prisma.wardenQuarantine.count({ where: { reviewedBy: null } }),
    prisma.wardenQuarantine.count({ where: { notes: 'denied' } }),
    prisma.wardenQuarantine.count({ where: { notes: 'released' } }),
    prisma.wardenQuarantine.count({ where: { reviewedBy: { not: null } } })
  ]);

  async function review(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role !== 'ADMIN') redirect('/');
    const id = String(formData.get('id'));
    const note = String(formData.get('note') ?? '');
    const q = await prisma.wardenQuarantine.update({
      where: { id },
      data: { reviewedBy: u.email, reviewedAt: new Date(), notes: note || null }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `quarantine:${note || 'reviewed'}`, target: q.recipient, detail: q.subject ?? q.msgId }
    });
    revalidatePath('/quarantine');
  }

  /** Undo a mis-click. The original decision stays in the audit log. */
  async function reopen(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/');
    const id = String(formData.get('id'));
    const q = await prisma.wardenQuarantine.update({
      where: { id },
      data: { reviewedBy: null, reviewedAt: null, notes: null }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'quarantine:reopened', target: q.recipient, detail: q.subject ?? q.msgId }
    });
    revalidatePath('/quarantine');
  }

  const day = (d: Date) => fmtTs(d);

  return (
    <div className="max-w-6xl space-y-4">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-lg font-semibold">
          <ShieldBan size={18} /> Quarantine
        </h1>
        <p className="text-sm text-text-muted">
          Messages your content-compliance rules held before delivery. They never reached a
          mailbox, which is why no scope can find them &mdash; Warden reads them from the Gmail
          delivery log. <strong className="text-text-primary">Release and deny happen in the
          Admin console</strong>; Google offers no API for either. Mark a row reviewed here once
          you have acted on it there.
        </p>
      </header>

      <IngestStatus f={fresh} what="quarantine" />

      {iocCount > 0 && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.6)' }}>
          <strong className="text-danger">
            {iocCount} held message{iocCount === 1 ? '' : 's'} match a known indicator.
          </strong>{' '}
          <span className="text-text-muted">
            These are part of a campaign Warden already knows about. Deny them, and check whether
            other copies got past the rule &mdash; run a scope on the lure text.
          </span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        {[
          ['open', `Not reviewed (${openCount})`],
          ['reviewed', `Reviewed (${reviewedCount})`],
          ['denied', `Denied (${deniedCount})`],
          ['released', `Released (${releasedCount})`],
          ['ioc', `Indicator match (${iocCount})`],
          ['all', 'Everything']
        ].map(([k, label]) => (
          <a
            key={k}
            href={`/quarantine?view=${k}`}
            className={`rounded border px-2.5 py-1 ${k === view ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
          >
            {label}
          </a>
        ))}
        <span className="ml-2 text-text-muted">Rule:</span>
        <a
          href={`/quarantine?view=${view}`}
          className={`rounded border px-2.5 py-1 ${!rule ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
        >
          all
        </a>
        {byRule
          .sort((a, b) => b._count._all - a._count._all)
          .map((r) => (
            <a
              key={r.ruleName ?? 'none'}
              href={`/quarantine?view=${view}&rule=${encodeURIComponent(r.ruleName ?? '')}`}
              className={`rounded border px-2.5 py-1 ${rule === r.ruleName ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
            >
              {r.ruleName ?? '(unnamed)'} ({r._count._all})
            </a>
          ))}
      </div>

      <p className="text-xs text-text-muted">
        {total.toLocaleString()} in this view{total > rows.length && <> &mdash; showing the most recent {rows.length}</>}.
      </p>

      {rows.length === 0 ? (
        <div className="card text-sm text-text-muted">
          {fresh.lastRunAt
            ? 'Nothing held in this view.'
            : 'The quarantine reader has not run yet. It runs on the scheduler every few minutes.'}
        </div>
      ) : (
        <div className="space-y-2">
          {rows.map((q) => (
            <div
              key={q.id}
              className="card text-sm"
              style={q.iocHit ? { borderColor: 'rgb(var(--danger) / 0.5)' } : undefined}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {q.iocHit && <span className="pill pill-critical">matches {q.iocHit}</span>}
                    <span className="pill pill-high">{q.ruleName ?? 'quarantined'}</span>
                    <span className="mono text-xs text-text-muted">{day(q.heldAt)}</span>
                  </div>
                  <div className="font-medium">{q.subject ?? '(no subject)'}</div>
                  <div className="mono text-xs text-text-muted">
                    {q.sender ? <>from {q.sender} &rarr; </> : <span title="Google does not record the sender on quarantine rows of the delivery log. Show original in the Admin console has it.">sender not logged &rarr; </span>}{q.recipient}
                    {q.senderIp && <> &middot; {q.senderIp}</>}
                    {q.attachments > 0 && <> &middot; {q.attachments} attachment{q.attachments === 1 ? '' : 's'}</>}
                  </div>
                  {q.matched && (
                    <div className="text-xs text-text-muted">
                      Rule matched on: <span className="mono text-text-primary">{q.matched}</span>
                    </div>
                  )}
                  <div className="text-xs text-text-muted">
                    <Link
                      href={`/scope?query=${encodeURIComponent(`rfc822msgid:${q.msgId} in:anywhere`)}`}
                      className="underline"
                    >
                      Did a copy get through? Scope this Message-ID
                    </Link>
                  </div>
                </div>

                <div className="w-64 shrink-0 space-y-1.5">
                  {q.reviewedBy ? (
                    <div className="text-xs text-text-muted">
                      Reviewed by {q.reviewedBy.split('@')[0]} {q.reviewedAt && day(q.reviewedAt)}
                      {' '}&middot;{' '}
                      <strong className="text-text-primary">{q.notes ?? 'decision not recorded'}</strong>
                      <form action={reopen} className="mt-1">
                        <input type="hidden" name="id" value={q.id} />
                        <button className="text-xs underline">undo — mark not reviewed</button>
                      </form>
                    </div>
                  ) : (
                    /*
                      One form per decision, with the decision as a hidden field. The first
                      version put both buttons in one form and relied on the clicked button's
                      name/value reaching the server action — it did not, so every review on
                      2026-10-01 was saved with no decision and audited only as "reviewed".
                    */
                    <div className="flex flex-wrap gap-1.5">
                      <form action={review}>
                        <input type="hidden" name="id" value={q.id} />
                        <input type="hidden" name="note" value="denied" />
                        <button className="btn btn-verdict text-xs">denied in console</button>
                      </form>
                      <form action={review}>
                        <input type="hidden" name="id" value={q.id} />
                        <input type="hidden" name="note" value="released" />
                        <button className="btn text-xs">released</button>
                      </form>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
