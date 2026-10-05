import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { fmtTs } from '@/lib/time';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { PendingButton } from '@/components/PendingButton';

export const dynamic = 'force-dynamic';

/**
 * The OAuth-grant queue: new apps granted access that can read or change mail, to apps not on
 * the allow-list. This is the token-takeover persistence a password reset does not revoke and
 * a mailbox sweep cannot see — the gap the Sept/Oct incidents exposed.
 *
 * A grant on ONE mailbox is the shape of a targeted takeover and leads the queue. A grant on
 * many (high fan-out) is usually an enterprise or ed-tech rollout to allow-list in one pass —
 * shown, but not alarming. Nothing here is auto-revoked; a human decides.
 */
const STATE_LABEL: Record<string, string> = {
  NEW: 'New',
  INVESTIGATING: 'Investigating',
  CONFIRMED_COMPROMISE: 'Confirmed',
  BENIGN: 'Benign',
  SUPPRESSED: 'Suppressed'
};

export default async function GrantsPage({
  searchParams
}: {
  searchParams: Promise<{ state?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { state = 'NEW' } = await searchParams;

  const where = state === 'ALL' ? {} : { state: state as never };
  const [flags, total, newCount] = await Promise.all([
    prisma.wardenGrantFlag.findMany({
      where,
      orderBy: [{ fanOut: 'asc' }, { ts: 'desc' }],
      take: 300
    }),
    prisma.wardenGrantFlag.count({ where }),
    prisma.wardenGrantFlag.count({ where: { state: 'NEW' } })
  ]);

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect('/grants?error=role');
    const id = String(formData.get('id'));
    const next = String(formData.get('state'));
    await prisma.wardenGrantFlag.update({
      where: { id },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `grant:${next}`, target: id }
    });
    revalidatePath('/grants');
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-lg font-semibold">OAuth grants</h1>
        <p className="text-sm text-text-muted">
          New apps granted access that can read or change mail — the persistence a password
          reset does not revoke. A grant on a single mailbox leads the queue; a grant on many
          is usually a rollout to allow-list by client ID in{' '}
          <a href="/settings?tab=OAuth+grants" className="underline">
            Settings &rarr; OAuth grants
          </a>
          .
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5 text-xs">
        {['NEW', 'INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN', 'ALL'].map((s) => (
          <a
            key={s}
            href={`/grants?state=${s}`}
            className={`rounded border px-2.5 py-1 ${
              s === state ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
            }`}
          >
            {s === 'ALL' ? 'All' : STATE_LABEL[s]}
            {s === 'NEW' && newCount > 0 ? ` (${newCount})` : ''}
          </a>
        ))}
      </div>

      {flags.length === 0 ? (
        <div className="card text-sm text-text-muted">
          Nothing in this view. If the watch is off, turn it on in{' '}
          <a href="/settings?tab=OAuth+grants" className="underline">
            Settings &rarr; OAuth grants
          </a>
          .
        </div>
      ) : (
        <div className="overflow-x-auto rounded border">
          <table className="w-full border-collapse bg-bg-surface">
            <thead className="border-b bg-bg-elevated">
              <tr>
                <th className="th w-16">Fan-out</th>
                <th className="th">Mailbox</th>
                <th className="th">App</th>
                <th className="th">What it can do</th>
                <th className="th w-40">When</th>
                <th className="th w-56">Triage</th>
              </tr>
            </thead>
            <tbody>
              {flags.map((f) => {
                const reasons: string[] = JSON.parse(f.reasons);
                const scopes: string[] = JSON.parse(f.scopes);
                const targeted = f.fanOut === 1;
                return (
                  <tr key={f.id} className="border-b last:border-0 align-top">
                    <td className="td">
                      <span className={`pill pill-${targeted ? 'high' : 'muted'}`}>{f.fanOut}</span>
                    </td>
                    <td className="td mono">{f.mailbox.split('@')[0]}</td>
                    <td className="td">
                      <div className="font-medium">{f.appName}</div>
                      <div className="mono text-xs text-text-muted">client {f.clientId}</div>
                      {f.ip && <div className="mono text-xs text-text-muted">{f.ip}</div>}
                    </td>
                    <td className="td">
                      <div className="mono text-xs text-text-muted">{scopes.join('  ')}</div>
                      <ul className="mt-1 space-y-0.5 text-xs text-text-muted">
                        {reasons.map((r, i) => (
                          <li key={i}>&bull; {r}</li>
                        ))}
                      </ul>
                    </td>
                    <td className="td mono text-text-muted">{fmtTs(f.ts)}</td>
                    <td className="td">
                      <div className="flex flex-wrap gap-1">
                        {(['INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN'] as const).map((s) => (
                          <form key={s} action={setState}>
                            <input type="hidden" name="id" value={f.id} />
                            <input type="hidden" name="state" value={s} />
                            <PendingButton
                              className={`btn px-2 py-1 text-xs ${s === 'CONFIRMED_COMPROMISE' ? 'btn-verdict' : ''}`}
                              pending="…"
                              disabled={f.state === s || user.role === 'ANALYST'}
                            >
                              {STATE_LABEL[s]}
                            </PendingButton>
                          </form>
                        ))}
                      </div>
                      <div className="mt-1 text-xs text-text-muted">
                        <a href={`/accounts?user=${encodeURIComponent(f.mailbox)}`} className="underline">
                          account
                        </a>
                        {f.reviewedBy && (
                          <>
                            {' '}
                            &middot; {STATE_LABEL[f.state]} &middot; {f.reviewedBy.split('@')[0]}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-xs text-text-muted">
        Read-only detection — Warden never revokes a grant. To stop a confirmed one, revoke the
        app for that mailbox in the Admin console (the user &rarr; Security &rarr; Connected
        applications) or with GAM. A native mail client (Outlook, Apple Mail) legitimately holds
        a mail scope, so a grant is a reason to <em>look</em>, not to alarm.
        {total > flags.length && <> Showing {flags.length} of {total} in this view.</>}
      </p>
    </div>
  );
}
