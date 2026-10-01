import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import Link from 'next/link';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { freshnessFor } from '@/lib/freshness';
import { IngestStatus, EmptyQueue } from '@/components/IngestStatus';
import { Siren } from 'lucide-react';

export const dynamic = 'force-dynamic';

const STATES = [
  'NEW', 'TRIAGED', 'INVESTIGATING', 'CONFIRMED_PHISH', 'SPAM',
  'CONFIRMED_COMPROMISE', 'KNOWN_GOOD', 'BENIGN', 'ALL'
] as const;

/**
 * Alert types whose verdict is about a MESSAGE. Everything else is about an ACCOUNT.
 *
 * A suspicious login is never "phish" or "spam", and a reported email is never a
 * "compromise" — offering all six verdicts on every row made half of them nonsense.
 */
/** Structural, not a type allowlist — see alerts/[id]/page.tsx for why. */
function isMailAlert(a: { rfcMessageId?: string | null; subject?: string | null }): boolean {
  return Boolean(a.rfcMessageId || a.subject);
}
const MAIL_ACTIONS = ['CONFIRMED_PHISH', 'SPAM', 'BENIGN'] as const;
const IDENTITY_ACTIONS = ['INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN'] as const;

const SEVERITY_PILL: Record<string, string> = {
  HIGH: 'pill-critical',
  MEDIUM: 'pill-high',
  LOW: 'pill-medium'
};

export default async function AlertsPage({
  searchParams
}: {
  searchParams: Promise<{ state?: string; type?: string; who?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { state = 'NEW', type, who = 'all' } = await searchParams;

  const cfg = await getSettings(prisma);
  const fresh = await freshnessFor(prisma, 'alerts', cfg.schedule.alertsMinutes);

  /**
   * Suspicious-login alerts for students are the bulk of this queue and almost all of it
   * is teenagers on VPNs — Cloudflare, OVH, whatever the app store is recommending this
   * term. They arrive faster than anyone will ever read them, and a queue nobody reads is
   * the same as no queue.
   *
   * `email` is the affected account on an identity alert. Gmail alerts have no email, so
   * they fall outside both audience filters rather than being silently counted as staff.
   */
  const home = (cfg.homeCountries || 'US').split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
  // Counted across the whole queue, not the 300 rows on screen — this is the number that
  // should make someone stop what they are doing.
  const foreignCount = await prisma.wardenAlert.count({
    where: { ...(state === 'ALL' ? {} : { state: state as never }), ipCountry: { not: null, notIn: home } }
  });

  const staffSuffix = `@${cfg.domains.staff}`;
  const studentSuffix = `@${cfg.domains.students}`;

  const audienceWhere =
    who === 'students'
      ? { email: { endsWith: studentSuffix } }
      : who === 'staff'
        ? { email: { endsWith: staffSuffix } }
        : {};

  const stateWhere = state === 'ALL' ? {} : { state: state as never };
  const where = { ...stateWhere, ...(type ? { type } : {}), ...audienceWhere };
  const studentWhere = { ...stateWhere, ...(type ? { type } : {}), email: { endsWith: studentSuffix } };

  const [staffCount, studentCount, studentNotable] = await Promise.all([
    prisma.wardenAlert.count({
      where: { ...stateWhere, ...(type ? { type } : {}), email: { endsWith: staffSuffix } }
    }),
    prisma.wardenAlert.count({ where: studentWhere }),
    /**
     * Student alerts that are NOT "a kid on a VPN". Shown above the bulk action so the
     * single look is an informed one.
     *
     * A leaked password or a Google-initiated suspension is a real finding on a student
     * account, and a student mailbox is trusted by staff precisely because it is internal.
     * Suspicious-login is the noisy type; everything else here is not.
     */
    prisma.wardenAlert.findMany({
      where: { ...studentWhere, NOT: { type: 'Suspicious login' } },
      orderBy: { createTime: 'desc' },
      take: 12,
      select: { alertId: true, type: true, email: true, createTime: true, ipOrg: true }
    })
  ]);

  const [alerts, byType, total] = await Promise.all([
    prisma.wardenAlert.findMany({ where, orderBy: { createTime: 'desc' }, take: 300 }),
    // Counted under the SAME state filter as the list. Without the where clause these
    // were all-time totals rendered beside the state tabs, so "User reported phishing
    // (312)" sat next to a NEW queue holding four of them.
    prisma.wardenAlert.groupBy({
      by: ['type'],
      where: { ...stateWhere, ...audienceWhere },
      _count: { _all: true }
    }),
    prisma.wardenAlert.count({ where })
  ]);

  // An alert that is mirrored into the report queue is triaged THERE. Showing verdict
  // buttons here as well asks the same person to judge the same thing twice.
  const mirrored = await prisma.wardenReport.findMany({
    where: { alertId: { in: alerts.map((a) => a.alertId) } },
    select: { id: true, alertId: true, state: true }
  });
  const repByAlert = new Map(mirrored.map((r) => [r.alertId!, r]));

  /**
   * Clear the student VPN noise in one pass.
   *
   * Scoped to exactly what the operator is looking at — current state tab, current type
   * filter, student domain — so it can never reach a staff alert. The counts are
   * recomputed inside the action rather than trusted from the form, because the ingest
   * runs every five minutes and the page was rendered some seconds ago.
   *
   * The audit row records how many of the dismissed alerts were NOT suspicious-login, so
   * a post-mortem can answer "did we wave past a student leaked-password alert".
   */
  async function dismissStudentAlerts(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect('/alerts?who=students&error=role');

    const c = await getSettings(prisma);
    const st = String(formData.get('state'));
    const ty = String(formData.get('type') ?? '');
    const scope = {
      ...(st === 'ALL' ? {} : { state: st as never }),
      ...(ty ? { type: ty } : {}),
      email: { endsWith: `@${c.domains.students}` }
    };

    const notable = await prisma.wardenAlert.count({
      where: { ...scope, NOT: { type: 'Suspicious login' } }
    });
    const res = await prisma.wardenAlert.updateMany({
      where: scope,
      data: { state: 'BENIGN' as never, reviewedBy: u.email, reviewedAt: new Date() }
    });

    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: 'alert:BENIGN:bulk-students',
        target: c.domains.students,
        resultCount: res.count,
        detail:
          `bulk-dismissed ${res.count} student alert${res.count === 1 ? '' : 's'} as benign` +
          (notable
            ? ` — ${notable} of them were NOT suspicious-login (leaked password, suspension or similar)`
            : ' — all were suspicious-login')
      }
    });
    revalidatePath('/alerts');
  }

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const id = String(formData.get('id'));
    const next = String(formData.get('state'));
    const a = await prisma.wardenAlert.update({
      where: { alertId: id },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `alert:${next}`, target: a.type, resultCount: 1 }
    });
    revalidatePath('/alerts');
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Alert Center</h1>
        <p className="text-sm text-text-muted">
          Google&rsquo;s own alerts, pulled through the API. Gmail&rsquo;s built-in &ldquo;Report
          phishing&rdquo; forwards nothing to anybody &mdash; it raises an alert here and that is
          the entire record, which is why these never reached the report mailbox.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex flex-wrap gap-1.5 text-xs">
          {STATES.map((s) => (
            <a
              key={s}
              href={`/alerts?state=${s}&who=${who}${type ? `&type=${encodeURIComponent(type)}` : ''}`}
              className={`rounded border px-2.5 py-1 ${
                s === state ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
              }`}
            >
              {s === 'ALL' ? 'All' : s.replace(/_/g, ' ')}
            </a>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5 text-xs">
        <a
          href={`/alerts?state=${state}&who=${who}`}
          className={`rounded border px-2.5 py-1 ${!type ? 'bg-bg-elevated' : 'text-text-muted'}`}
        >
          all types
        </a>
        {byType
          .sort((a, b) => b._count._all - a._count._all)
          .map((t) => (
            <a
              key={t.type}
              href={`/alerts?state=${state}&who=${who}&type=${encodeURIComponent(t.type)}`}
              className={`rounded border px-2.5 py-1 ${
                t.type === type ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
              }`}
            >
              {t.type} ({t._count._all})
            </a>
          ))}
      </div>

      {/*
        Staff and students are different problems on this queue too. A student suspicious
        login is usually a VPN; a staff one is how a district gets compromised.
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
            href={`/alerts?state=${state}&who=${key}${type ? `&type=${encodeURIComponent(type)}` : ''}`}
            className={`rounded border px-2.5 py-1 ${
              key === who ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
            }`}
          >
            {label as string} <span className="text-text-muted">({n as number})</span>
          </a>
        ))}
      </div>

      {studentCount > 0 && user.role !== 'ANALYST' && (
        <div className="card space-y-3">
          <div className="text-sm font-medium">
            Clear {studentCount} student alert{studentCount === 1 ? '' : 's'} in one pass
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
                They are not suspicious-login alerts, so they are not explained by a VPN.
                Students get phished too, and a student mailbox is trusted by staff
                precisely because it is internal.
                <ul className="mt-2 space-y-1">
                  {studentNotable.map((a) => (
                    <li key={a.alertId} className="mono text-xs">
                      <span className="pill pill-high">{a.type}</span> {a.email} &middot;{' '}
                      {a.createTime.toISOString().slice(0, 16).replace('T', ' ')}Z
                      {a.ipOrg ? ` · ${a.ipOrg}` : ''}
                    </li>
                  ))}
                </ul>
              </div>
              <p className="text-xs text-text-muted">
                Dismissing now marks those {studentNotable.length} benign too. To keep them,
                set them to Investigating first, or filter to
                <span className="mono"> Suspicious login</span> above and dismiss only that
                type.
              </p>
            </>
          ) : (
            <p className="text-sm text-text-muted">
              Every one of these is a suspicious-login alert &mdash; no leaked passwords, no
              suspensions. This looks like ordinary VPN noise.
            </p>
          )}

          <form action={dismissStudentAlerts}>
            <input type="hidden" name="state" value={state} />
            <input type="hidden" name="type" value={type ?? ''} />
            <button className="btn text-xs">
              Mark all {studentCount} student alert{studentCount === 1 ? '' : 's'} benign
              {type ? ` (${type} only)` : ''}
            </button>
          </form>
          <p className="text-xs text-text-muted">
            Reversible &mdash; they move to the Benign tab, nothing is deleted, and the audit
            log records the count and your name. Staff alerts are never touched by this
            button. It acts on the current state and type filters only.
          </p>
        </div>
      )}

      {foreignCount > 0 && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.6)' }}>
          <strong className="text-danger">
            {foreignCount} alert{foreignCount === 1 ? '' : 's'} in this view from an IP registered
            outside {home.join('/')}.
          </strong>{' '}
          <span className="text-text-muted">
            Marked with a red pill below and never auto-filed. The country is where the network is
            registered, not where the person is — a foreign ISP is strong evidence, a US-registered
            VPN or cloud range can still exit anywhere. Confirm with the user before closing.
          </span>
        </div>
      )}

      <IngestStatus f={fresh} what="alert" />

      {alerts.length === 0 ? (
        <EmptyQueue f={fresh} what="alert" />
      ) : (
        <>
          <p className="text-xs text-text-muted">
            {total.toLocaleString()} alert{total === 1 ? '' : 's'} in this view
            {total > 300 && <> &mdash; showing the most recent 300</>}.
          </p>
          <div className="space-y-2">
            {alerts.map((a) => {
              const isMail = isMailAlert(a);
              const actions = isMail ? MAIL_ACTIONS : IDENTITY_ACTIONS;
              const rep = repByAlert.get(a.alertId);
              return (
                <div key={a.alertId} className="card">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`pill ${SEVERITY_PILL[a.severity ?? ''] ?? 'pill-muted'}`}>
                          {a.severity ?? '—'}
                        </span>
                        <Link href={`/alerts/${a.alertId}`} className="font-medium underline-offset-2 hover:underline">{a.type}</Link>
                        <span className="text-xs text-text-muted">
                          {a.createTime.toISOString().slice(0, 16).replace('T', ' ')}
                        </span>
                      </div>
                      {a.subject && (<Link href={`/alerts/${a.alertId}`} className="mt-1 block break-words text-sm underline-offset-2 hover:underline">{a.subject}</Link>)}
                      <div className="mono mt-1 break-all text-xs text-text-muted">
                        {a.fromHeader && <>from {a.fromHeader} &middot; </>}
                        {a.recipient && <>to {a.recipient}</>}
                        {a.email && <>{a.email}</>}
                        {a.ip && <> &middot; {a.ip}</>}
                        {a.messageCount > 1 && <> &middot; {a.messageCount} messages</>}
                      </div>
                      {/* Who owns the address is the whole judgement on a sign-in, and it is
                          the one thing Google does not tell you. */}
                      {a.ipOrg && (
                        <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs">
                          {a.ipCountry && !home.includes(a.ipCountry.toUpperCase()) && (
                            <span className="pill pill-critical font-semibold">
                              OUTSIDE {home.join('/')} &middot; {a.ipCountry}
                            </span>
                          )}
                          <span
                            className={`pill ${
                              a.ipClass === 'anonymizer'
                                ? 'pill-high'
                                : a.ipClass === 'residential'
                                  ? 'pill-ok'
                                  : 'pill-muted'
                            }`}
                          >
                            {a.ipClass === 'anonymizer'
                              ? 'VPN / hosting'
                              : a.ipClass === 'residential'
                                ? 'residential'
                                : 'unclassified'}
                          </span>
                          <span className="text-text-muted">{a.ipOrg}</span>
                          {a.ipNet && <span className="mono text-text-muted">{a.ipNet}</span>}
                        </div>
                      )}
                    </div>

                    {/* Fixed-width action column so verdicts line up down the page rather
                        than drifting with the length of each subject line. */}
                    <div className="flex shrink-0 flex-wrap gap-1 sm:w-60 sm:justify-end">
                      {rep ? (
                        <Link
                          href={`/reports/${rep.id}`}
                          className="btn px-2 py-1 text-xs"
                          title="This alert is the same event as a report. Triage it there once."
                        >
                          in reports: {rep.state.replace(/_/g, ' ').toLowerCase()} &rarr;
                        </Link>
                      ) : (
                        actions.map((st) => (
                          <form key={st} action={setState}>
                            <input type="hidden" name="id" value={a.alertId} />
                            <input type="hidden" name="state" value={st} />
                            <button
                              className={`btn px-2 py-1 text-xs ${
                                st === 'CONFIRMED_PHISH' || st === 'CONFIRMED_COMPROMISE'
                                  ? 'btn-verdict'
                                  : ''
                              }`}
                            >
                              {st.replace(/_/g, ' ').toLowerCase()}
                            </button>
                          </form>
                        ))
                      )}
                    </div>
                  </div>

                  {a.bodySnippet && (
                    <div className="mt-2 text-xs text-text-muted">{a.bodySnippet.slice(0, 300)}</div>
                  )}
                  {a.rfcMessageId && (
                    <div className="mt-2 text-xs">
                      <span className="text-text-muted">scope the whole domain with: </span>
                      <code className="mono rounded bg-bg-elevated px-1.5 py-0.5 break-all">
                        rfc822msgid:{a.rfcMessageId}
                      </code>
                    </div>
                  )}
                  {a.notes && <div className="mt-2 text-xs text-text-muted">{a.notes}</div>}
                </div>
              );
            })}
          </div>
        </>
      )}

      <p className="text-xs text-text-muted">
        Pulled from the API rather than from Google&rsquo;s alert emails, which arrive up to 24
        hours late and carry far less. Verdicts differ by kind on purpose: a sign-in is judged
        as an account question, a reported message as a mail question.
      </p>
    </div>
  );
}
