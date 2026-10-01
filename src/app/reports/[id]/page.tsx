import { redirect, notFound } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import Link from 'next/link';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { defang } from '@/lib/reports';
import { getSettings } from '@/lib/settings';
import { triageMessage, triageBody, type TriageVerdict } from '@/lib/ai';
import { ArrowLeft, TriangleAlert, Sparkles } from 'lucide-react';
import { PendingButton } from '@/components/PendingButton';

export const dynamic = 'force-dynamic';

/**
 * What each AI status means in words an analyst can act on. The raw status strings are
 * for logs; a person at 22:00 needs to know whether to wait, retry, or stop expecting it.
 */
const AI_EXPLAIN: Record<string, string> = {
  disabled: 'Claude triage is switched off in Settings → Claude.',
  unavailable:
    'The Claude CLI could not be started on this host, or its session has expired. ' +
    'Re-authenticate with: ssh -L 8765:localhost:8765 to the Warden host, then ' +
    'sudo -u warden -H claude and follow the URL. Triage is optional — everything else works.',
  timeout: 'Claude did not answer within the configured timeout. Raise it in Settings → Claude, or retry.',
  bad_output: 'Claude replied, but not with the JSON this page expects. The raw reply is below.'
};

const STATES = ['NEW', 'TRIAGED', 'CONFIRMED_PHISH', 'SPAM', 'KNOWN_GOOD', 'BENIGN', 'DUPLICATE'] as const;

export default async function ReportDetail({ params }: { params: Promise<{ id: string }> }) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { id } = await params;

  const report = await prisma.wardenReport.findUnique({ where: { id } });
  if (!report) notFound();

  const hosts = JSON.parse(report.payloadHosts ?? '[]') as string[];
  const urls = JSON.parse(report.payloadUrls ?? '[]') as string[];

  // Everyone else who reported the same thing. A single report is an opinion; forty are a
  // campaign, and the count is usually the fastest thing to judge on.
  const siblings = report.originalSubject
    ? await prisma.wardenReport.findMany({
        where: {
          id: { not: report.id },
          originalSubject: { contains: report.originalSubject.slice(0, 40) }
        },
        orderBy: { reportedAt: 'desc' },
        take: 50,
        select: { id: true, reporter: true, reportedAt: true, state: true }
      })
    : [];

  // take:50 is a ceiling, and rendering it as "50 other reports" presents a cap as a
  // measurement — on a 71-report campaign it reads 50 and the analyst under-scopes.
  const siblingTotal = report.originalSubject
    ? await prisma.wardenReport.count({
        where: {
          id: { not: report.id },
          originalSubject: { contains: report.originalSubject.slice(0, 40) }
        }
      })
    : 0;

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const next = String(formData.get('state'));
    const rid = String(formData.get('id'));
    const r = await prisma.wardenReport.update({
      where: { id: rid },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    // Keep the Alert Center twin in step — one event, one decision.
    if (r.alertId) {
      await prisma.wardenAlert.update({
        where: { alertId: r.alertId },
        data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
      }).catch(() => undefined);
    }
    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: `report:${next}`,
        target: r.originalSubject ?? r.msgId,
        resultCount: 1
      }
    });
    revalidatePath(`/reports/${rid}`);
    revalidatePath('/reports');
    revalidatePath('/alerts');
  }

  /**
   * Run Claude over this one message, on demand.
   *
   * NEVER automatic. The CLI is serialised against a single interactive session, so
   * triaging a 60-report campaign automatically would queue 60 calls and rate-limit the
   * session mid-incident. An analyst asks for the one message they are actually looking at.
   *
   * The result is advisory and is stored, not acted upon. Nothing here changes the report
   * state; the verdict buttons above remain the only thing that does, and a human presses
   * them. aiRanBy records who asked.
   */
  async function runTriage(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const rid = String(formData.get('id'));

    const r = await prisma.wardenReport.findUnique({ where: { id: rid } });
    if (!r) return;

    const s = await getSettings(prisma);
    // Synthesised from what the ingest parsed. The original RFC822 headers are not stored;
    // say so rather than implying the model saw a full header block.
    const headers = [
      `From: ${r.originalSender ?? '(not parsed)'}`,
      `To: ${r.originalTo ?? '(not parsed)'}`,
      `Subject: ${r.originalSubject ?? '(not parsed)'}`,
      `Reported-By: ${r.reporter}`,
      `Reported-At: ${r.reportedAt.toISOString()}`
    ].join('\n');

    const res = await triageMessage(
      s.ai,
      headers,
      triageBody(r.bodyText ?? '', JSON.parse(r.payloadUrls ?? '[]') as string[])
    );

    await prisma.wardenReport.update({
      where: { id: rid },
      data: {
        aiStatus: res.status,
        aiVerdict: res.status === 'ok' && res.data ? JSON.stringify(res.data) : (res.raw ?? null),
        aiRanAt: new Date(),
        aiRanBy: u.email
      }
    });
    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: `report:ai-triage:${res.status}`,
        target: r.originalSubject ?? r.msgId,
        resultCount: 1
      }
    });
    revalidatePath(`/reports/${rid}`);
  }

  const verdict: TriageVerdict | null =
    report.aiStatus === 'ok' && report.aiVerdict
      ? (() => {
          try {
            return JSON.parse(report.aiVerdict) as TriageVerdict;
          } catch {
            return null;
          }
        })()
      : null;

  return (
    <div className="max-w-5xl space-y-4">
      <Link href="/reports" className="inline-flex items-center gap-1 text-sm text-text-muted">
        <ArrowLeft size={14} /> All reports
      </Link>

      <header className="space-y-1">
        <h1 className="text-lg font-semibold">{report.originalSubject || '(no subject parsed)'}</h1>
        <div className="text-sm text-text-muted">
          Reported by <span className="mono">{report.reporter}</span> on{' '}
          {report.reportedAt.toISOString().slice(0, 16).replace('T', ' ')}
          {report.reportedTo && (
            <>
              {' '}
              to <span className="mono">{report.reportedTo}</span>
            </>
          )}
        </div>
      </header>

      <div className="card space-y-2">
        <table className="w-full border-collapse text-sm">
          <tbody>
            {[
              ['Original sender', report.originalSender ?? 'not parsed'],
              ['Original recipients', report.originalTo ?? 'not parsed'],
              ['Current state', report.state.replace('_', ' ')],
              report.reviewedBy ? ['Reviewed by', `${report.reviewedBy} ${report.reviewedAt?.toISOString().slice(0, 10) ?? ''}`] : null,
              ['Gmail message id', report.msgId]
            ]
              .filter(Boolean)
              .map((row) => {
                const [k, v] = row as [string, string];
                return (
                  <tr key={k} className="border-b last:border-0">
                    <td className="td w-48 text-text-muted">{k}</td>
                    <td className="td mono break-all">{v}</td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {STATES.filter((s) => s !== report.state).map((s) => (
          <form key={s} action={setState}>
            <input type="hidden" name="id" value={report.id} />
            <input type="hidden" name="state" value={s} />
            <button className={`btn text-xs ${s === 'CONFIRMED_PHISH' ? 'btn-verdict' : ''}`}>
              mark {s.replace('_', ' ').toLowerCase()}
            </button>
          </form>
        ))}
      </div>

      {(urls.length > 0 || hosts.length > 0) && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2 text-sm font-medium">
            <TriangleAlert size={15} style={{ color: 'rgb(var(--danger))' }} /> Extracted links
          </div>
          <p className="text-xs text-text-muted">
            Shown defanged and deliberately not clickable. Every URL here is assumed hostile,
            and browsers prefetch. Redirect wrappers have already been unwrapped &mdash; a
            payload behind <span className="mono">google.com/url?q=</span> once survived a
            verification that reported clean.
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
        <div className="text-sm font-medium">The reported message</div>
        {report.bodyText ? (
          <>
            <pre className="mono max-h-[36rem] overflow-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs leading-relaxed">
              {report.bodyText}
            </pre>
            {report.bodyText.length >= 64_000 && (
              <p className="text-xs text-text-muted">
                Truncated at 64,000 characters.
              </p>
            )}
          </>
        ) : (
          <p className="text-sm text-text-muted">
            No body stored for this report. It was ingested before bodies were captured &mdash;
            re-run <code className="mono">scripts/ingest-reports.ts</code> and it will be
            backfilled in place without disturbing its triage state.
          </p>
        )}
      </div>

      {/*
        Placed AFTER the message body on purpose. An analyst who reads a verdict first
        reads the message looking for confirmation of it. The order here is: the evidence,
        then somebody's opinion of the evidence.
      */}
      <div className="card space-y-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Sparkles size={15} /> Claude triage
        </div>
        <p className="text-xs text-text-muted">
          <strong className="text-text-primary">Advisory only.</strong> This is a second
          opinion, not a decision and not evidence. It cannot change this report&rsquo;s state,
          scope a query, or touch a mailbox &mdash; only the buttons above do that, and only
          when a person presses them. Claude is wrong sometimes and is confident when it is.
        </p>
        <p className="text-xs text-text-muted">
          <strong className="text-text-primary">What the button does:</strong> sends this
          message&rsquo;s sender, recipient, subject, every link Warden extracted, and the{' '}
          <strong className="text-text-primary">first 6,000 characters of the message as plain text</strong> to
          Claude (Anthropic) through the CLI on the Warden server &mdash; nothing else leaves the
          server. Claude returns a verdict and its reasoning, the payload hosts with redirect
          wrappers decoded, distinctive lure phrases, who it impersonates, and a suggested scope
          query. The result is saved here with your name so everyone sees the same answer. Links
          go first and HTML styling is stripped, so a padded message &mdash; blank spacers hiding a
          stolen thread to fool filters &mdash; still shows Claude the lure and its link.
        </p>

        {report.aiStatus === 'ok' && verdict ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`pill ${verdict.isPhish ? 'pill-critical' : 'pill-muted'}`}>
                {verdict.isPhish ? 'reads as phishing' : 'reads as not phishing'}
              </span>
              <span className="pill pill-muted">{verdict.confidence} confidence</span>
              {verdict.impersonates && (
                <span className="pill pill-high">impersonates {verdict.impersonates}</span>
              )}
            </div>

            <p className="text-sm">{verdict.reasoning}</p>

            {verdict.lureStrings?.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs text-text-muted">
                  Distinctive phrases &mdash; these are what a scope query should match, because
                  Gmail cannot reliably find a bare domain inside a link.
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {verdict.lureStrings.map((l) => (
                    <span key={l} className="pill pill-muted mono text-xs">{l}</span>
                  ))}
                </div>
              </div>
            )}

            {verdict.payloadHosts?.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs text-text-muted">
                  Payload hosts it claims to have found, defanged. Check these against the
                  extracted links above &mdash; if they disagree, trust the extractor.
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {verdict.payloadHosts.map((h) => (
                    <span key={h} className="pill pill-critical mono text-xs">
                      {h.replace(/\./g, '[.]')}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {verdict.suggestedScopeQuery && (
              <div className="space-y-1">
                <div className="text-xs text-text-muted">
                  Suggested scope query &mdash; <strong className="text-text-primary">read it
                  before you run it.</strong> A query scoped on sender alone would have destroyed
                  51 live special-education messages; Scope refuses those, but it cannot catch
                  a query that is merely too broad.
                </div>
                <pre className="mono overflow-x-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs">
                  {verdict.suggestedScopeQuery}
                </pre>
              </div>
            )}
          </>
        ) : report.aiStatus ? (
          <div className="space-y-2">
            <span className="pill pill-muted">{report.aiStatus.replace('_', ' ')}</span>
            <p className="text-sm text-text-muted">
              {AI_EXPLAIN[report.aiStatus] ?? 'Triage did not return a usable answer.'}
            </p>
            {report.aiStatus === 'bad_output' && report.aiVerdict && (
              <pre className="mono max-h-48 overflow-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 text-xs">
                {report.aiVerdict}
              </pre>
            )}
          </div>
        ) : (
          <p className="text-sm text-text-muted">Not run for this report.</p>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <form action={runTriage}>
            <input type="hidden" name="id" value={report.id} />
            <PendingButton
              disabled={!report.bodyText}
              pending="Asking Claude… (up to a minute)"
            >
              {report.aiStatus ? 'Run again' : 'Run Claude triage'}
            </PendingButton>
          </form>
          {!report.bodyText && (
            <span className="text-xs text-text-muted">
              No message body stored, so there is nothing to triage.
            </span>
          )}
          {report.aiRanAt && (
            <span className="text-xs text-text-muted">
              Last run {report.aiRanAt.toISOString().slice(0, 16).replace('T', ' ')}
              {report.aiRanBy ? ` by ${report.aiRanBy}` : ''}. Runs take up to a minute.
            </span>
          )}
        </div>
      </div>

      {siblings.length > 0 && (
        <div className="card space-y-2">
          <div className="text-sm font-medium">
            {siblingTotal} other report{siblingTotal === 1 ? '' : 's'} of the same subject
            {siblingTotal > siblings.length && <> &mdash; showing {siblings.length}</>}
          </div>
          <table className="w-full border-collapse">
            <thead className="border-b">
              <tr>
                <th className="th w-32">Reported</th>
                <th className="th">Reporter</th>
                <th className="th w-32">State</th>
              </tr>
            </thead>
            <tbody>
              {siblings.map((s) => (
                <tr key={s.id} className="border-b last:border-0">
                  <td className="td mono text-xs">{s.reportedAt.toISOString().slice(0, 10)}</td>
                  <td className="td">
                    <Link href={`/reports/${s.id}`} className="mono text-xs underline">
                      {s.reporter}
                    </Link>
                  </td>
                  <td className="td">
                    <span className="pill pill-muted">{s.state.replace('_', ' ')}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
