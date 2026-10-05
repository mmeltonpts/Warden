import { redirect, notFound } from 'next/navigation';
import { fmtTs, fmtDate } from '@/lib/time';
import { revalidatePath } from 'next/cache';
import Link from 'next/link';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { errText } from '@/lib/errors';
import { defang } from '@/lib/reports';
import { ArrowLeft, TriangleAlert, ExternalLink } from 'lucide-react';

export const dynamic = 'force-dynamic';

/**
 * Verdicts that exist on BOTH WardenAlertState and WardenReportState. Anything outside
 * this set is an alert-only verdict and must not be pushed at the report.
 */
const MIRRORABLE = new Set(['NEW', 'TRIAGED', 'CONFIRMED_PHISH', 'KNOWN_GOOD', 'SPAM', 'BENIGN', 'DUPLICATE']);

/**
 * Is this alert ABOUT a message, or about an identity?
 *
 * Decided structurally, from whether Google gave us a message to look at, rather than from
 * a two-item list of type strings. The allowlist was
 * `['User reported phishing', 'User reported spam spike']`, and Google raises message-level
 * alerts under other names — "Suspicious message reported", "Phishing in inboxes due to bad
 * whitelist". Those fell through to the identity branch, which offered **confirmed
 * compromise** as a verdict on an email.
 */
function isMailAlert(a: { rfcMessageId?: string | null; subject?: string | null }): boolean {
  return Boolean(a.rfcMessageId || a.subject);
}
const MAIL_ACTIONS = ['CONFIRMED_PHISH', 'SPAM', 'KNOWN_GOOD', 'BENIGN', 'TRIAGED'] as const;
const IDENTITY_ACTIONS = ['INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN', 'TRIAGED'] as const;

const SEVERITY_PILL: Record<string, string> = {
  HIGH: 'pill-critical',
  MEDIUM: 'pill-high',
  LOW: 'pill-medium'
};

export default async function AlertDetail({ params }: { params: Promise<{ id: string }> }) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { id } = await params;

  const alert = await prisma.wardenAlert.findUnique({ where: { alertId: id } });
  if (!alert) notFound();

  // The full message lives on the report, because that is where the body fetch stores it.
  const report = await prisma.wardenReport.findFirst({ where: { alertId: alert.alertId } });
  const hosts = JSON.parse(report?.payloadHosts ?? '[]') as string[];
  const urls = JSON.parse(report?.payloadUrls ?? '[]') as string[];
  const shas = JSON.parse(alert.attachmentSha ?? '[]') as string[];

  // Other sign-ins from the same network, so "is this normal for us" is answerable here.
  const sameNet = alert.ipNet
    ? await prisma.wardenAlert.findMany({
        where: { ipNet: alert.ipNet, alertId: { not: alert.alertId } },
        orderBy: { createTime: 'desc' },
        take: 12,
        select: { alertId: true, email: true, createTime: true, state: true }
      })
    : [];

  const isMail = isMailAlert(alert);
  const actions = isMail ? MAIL_ACTIONS : IDENTITY_ACTIONS;

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const aid = String(formData.get('id'));
    const next = String(formData.get('state'));
    const a = await prisma.wardenAlert.update({
      where: { alertId: aid },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    /**
     * Keep the mirrored report in step — one event, one decision.
     *
     * Only for verdicts that EXIST on both sides. WardenReportState has no INVESTIGATING
     * and no CONFIRMED_COMPROMISE, so those two threw an invalid-enum error that
     * `.catch(() => undefined)` swallowed: the alert moved, the report silently did not,
     * and the comment above claimed they were in step. A divergence nobody is told about
     * is worse than no mirroring at all, because the next person trusts it.
     */
    if (MIRRORABLE.has(next)) {
      const mirrored = await prisma.wardenReport
        .updateMany({
          where: { alertId: aid },
          data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
        })
        .catch((e) => ({ count: -1, error: errText(e) }));

      if ('error' in mirrored) {
        // Do not swallow. Record it where a post-mortem will find it.
        await prisma.wardenAudit.create({
          data: {
            operator: u.email,
            action: 'alert_mirror_FAILED',
            target: aid,
            detail: `alert set to ${next} but the mirrored report did not follow: ${mirrored.error}`
          }
        });
      }
    }
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `alert:${next}`, target: a.type, resultCount: 1 }
    });
    revalidatePath(`/alerts/${aid}`);
    revalidatePath('/alerts');
    revalidatePath('/reports');
  }

  const rows: Array<[string, string | null]> = [
    ['Type', alert.type],
    ['Source', alert.source],
    ['Severity', alert.severity],
    ['Google status', alert.googleState],
    ['Raised', fmtTs(alert.createTime)],
    ['Window', alert.startTime && alert.endTime
      ? `${fmtTs(alert.startTime)} → ${fmtTs(alert.endTime)}`
      : null],
    ['Account', alert.email],
    ['Sender', alert.fromHeader],
    ['Recipient', alert.recipient],
    ['Messages in alert', alert.messageCount ? String(alert.messageCount) : null],
    ['IP address', alert.ip],
    ['Network owner', alert.ipOrg],
    ['Allocation', alert.ipNet],
    ['Reviewed by', alert.reviewedBy ? `${alert.reviewedBy} ${fmtDate(alert.reviewedAt)}` : null],
    ['Alert ID', alert.alertId]
  ];

  return (
    <div className="max-w-5xl space-y-4">
      <Link href="/alerts" className="inline-flex items-center gap-1 text-sm text-text-muted">
        <ArrowLeft size={14} /> All alerts
      </Link>

      <header className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`pill ${SEVERITY_PILL[alert.severity ?? ''] ?? 'pill-muted'}`}>
            {alert.severity ?? '—'}
          </span>
          <h1 className="text-lg font-semibold">{alert.type}</h1>
          <span className="pill pill-muted">{alert.state.replace(/_/g, ' ').toLowerCase()}</span>
        </div>
        {alert.subject && <p className="break-words text-sm">{alert.subject}</p>}
      </header>

      {alert.ipClass && (
        <div
          className="card text-sm"
          style={{
            borderColor:
              alert.ipClass === 'anonymizer' ? 'rgb(var(--warning) / 0.4)' : undefined
          }}
        >
          {alert.ipClass === 'anonymizer' ? (
            <>
              <strong>{alert.ipOrg}</strong> is a VPN, proxy or hosting network. This was
              deliberately left for review rather than auto-filed &mdash; somebody doing
              homework is not in a datacentre. For a pupil it is most often filter evasion,
              but it is an anonymiser and that is the one case worth reading.
            </>
          ) : alert.ipClass === 'residential' ? (
            <>
              <strong>{alert.ipOrg}</strong> is a residential or mobile-carrier network. A new
              consumer IPv6 delegation is not travel &mdash; Comcast and T-Mobile rotate them
              constantly, and Google raises an alert each time.
            </>
          ) : (
            <>
              Network owner could not be classified. <strong>{alert.ipOrg || 'Unknown'}</strong>{' '}
              is neither in the residential nor the VPN list in Settings.
            </>
          )}
        </div>
      )}

      <div className="flex flex-wrap gap-1.5">
        {actions
          .filter((s) => s !== alert.state)
          .map((s) => (
            <form key={s} action={setState}>
              <input type="hidden" name="id" value={alert.alertId} />
              <input type="hidden" name="state" value={s} />
              <button
                className={`btn text-xs ${
                  s === 'CONFIRMED_PHISH' || s === 'CONFIRMED_COMPROMISE' ? 'btn-verdict' : ''
                }`}
              >
                mark {s.replace(/_/g, ' ').toLowerCase()}
              </button>
            </form>
          ))}
      </div>

      <div className="card">
        <table className="w-full border-collapse text-sm">
          <tbody>
            {rows
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <tr key={k} className="border-b last:border-0">
                  <td className="td w-48 text-text-muted">{k}</td>
                  <td className="td mono break-all">{v}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {(urls.length > 0 || hosts.length > 0) && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2 text-sm font-medium">
            <TriangleAlert size={15} style={{ color: 'rgb(var(--danger))' }} /> Extracted links
          </div>
          <p className="text-xs text-text-muted">
            Defanged and deliberately not clickable &mdash; every URL here is assumed hostile
            and browsers prefetch.
          </p>
          {hosts.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {hosts.map((h) => (
                <span key={h} className="pill pill-critical mono">
                  {h.replace(/\./g, '[.]')}
                </span>
              ))}
            </div>
          )}
          {urls.length > 0 && (
            <pre className="mono overflow-x-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs">
              {urls.map((u) => defang(u)).join('\n')}
            </pre>
          )}
        </div>
      )}

      <div className="card space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm font-medium">The reported message</div>
          {report && (
            <Link href={`/reports/${report.id}`} className="btn px-2 py-1 text-xs">
              open in reports &rarr;
            </Link>
          )}
        </div>
        {report?.bodyText ? (
          <pre className="mono max-h-[40rem] overflow-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs leading-relaxed">
            {report.bodyText}
          </pre>
        ) : alert.bodySnippet ? (
          <>
            <pre className="mono overflow-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs">
              {alert.bodySnippet}
            </pre>
            <p className="text-xs text-text-muted">
              This is Google&rsquo;s snippet, which is all the Alert Center returns. The full
              message is fetched from the reporter&rsquo;s mailbox by{' '}
              <code className="mono">scripts/ingest-alerts.ts</code> when &ldquo;Fetch the
              reported message body&rdquo; is on in Settings &mdash; it may have been deleted
              since.
            </p>
          </>
        ) : (
          <p className="text-sm text-text-muted">
            No message body. This alert is about an account, not an email.
          </p>
        )}
      </div>

      {shas.length > 0 && (
        <div className="card space-y-1">
          <div className="text-sm font-medium">Attachment SHA-256</div>
          <pre className="mono overflow-x-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs">
            {shas.join('\n')}
          </pre>
        </div>
      )}

      {alert.rfcMessageId && (
        <div className="card space-y-1">
          <div className="text-sm font-medium">Scope this across the domain</div>
          <pre className="mono overflow-x-auto rounded bg-bg-elevated p-3 text-xs">
            rfc822msgid:{alert.rfcMessageId}
          </pre>
          <Link
            href={`/scope?query=${encodeURIComponent(`rfc822msgid:${alert.rfcMessageId} in:anywhere`)}`}
            className="btn text-xs"
          >
            Open this in Scope
          </Link>
          <p className="text-xs text-text-muted">
            One person&rsquo;s report becomes a domain-wide search, to find every other copy.
            The button fills the query in for you &mdash; a hand-copied 60-character
            Message-ID that loses a few characters returns zero hits, and zero hits reads
            as &ldquo;not spreading&rdquo;.
          </p>
        </div>
      )}

      {sameNet.length > 0 && (
        <div className="card space-y-2">
          <div className="text-sm font-medium">
            {sameNet.length} other sign-in{sameNet.length === 1 ? '' : 's'} from{' '}
            <span className="mono">{alert.ipNet}</span>
          </div>
          <table className="w-full border-collapse">
            <thead className="border-b">
              <tr>
                <th className="th w-32">When</th>
                <th className="th">Account</th>
                <th className="th w-36">State</th>
              </tr>
            </thead>
            <tbody>
              {sameNet.map((o) => (
                <tr key={o.alertId} className="border-b last:border-0">
                  <td className="td mono text-xs">{fmtDate(o.createTime)}</td>
                  <td className="td">
                    <Link href={`/alerts/${o.alertId}`} className="mono text-xs underline">
                      {o.email}
                    </Link>
                  </td>
                  <td className="td">
                    <span className="pill pill-muted">{o.state.replace(/_/g, ' ')}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {alert.investigateLink && (
        <a
          href={
            alert.investigateLink.startsWith('http')
              ? alert.investigateLink
              : `https://${alert.investigateLink}`
          }
          target="_blank"
          rel="noopener noreferrer"
          className="btn inline-flex items-center gap-1 text-xs"
        >
          <ExternalLink size={13} /> Open in Google&rsquo;s security investigation tool
        </a>
      )}

      {alert.notes && <p className="text-xs text-text-muted">{alert.notes}</p>}
    </div>
  );
}
