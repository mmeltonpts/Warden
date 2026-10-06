import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { fmtTs } from '@/lib/time';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings, saveSettings } from '@/lib/settings';
import { PendingButton } from '@/components/PendingButton';

export const dynamic = 'force-dynamic';

/**
 * The OAuth-grant queue, GROUPED BY APP (client ID). One enterprise rollout — the district's
 * Phish Alert add-on on 600+ mailboxes — is one decision, not 2,000 rows, so each app is a
 * single expandable card. A grant on one mailbox is the targeted-takeover shape and leads the
 * queue; a grant on many is usually a rollout to allow-list in one click. Nothing is
 * auto-revoked; a human decides.
 */
const STATE_LABEL: Record<string, string> = {
  NEW: 'New',
  INVESTIGATING: 'Investigating',
  CONFIRMED_COMPROMISE: 'Confirmed',
  BENIGN: 'Benign',
  SUPPRESSED: 'Suppressed'
};
const FETCH_CAP = 5000;

export default async function GrantsPage({
  searchParams
}: {
  searchParams: Promise<{ state?: string; error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { state = 'NEW', error } = await searchParams;
  const canAct = user.role !== 'ANALYST';
  const isAdmin = user.role === 'ADMIN';

  const where = state === 'ALL' ? {} : { state: state as never };
  const [rows, total, newCount] = await Promise.all([
    prisma.wardenGrantFlag.findMany({
      where,
      orderBy: [{ ts: 'desc' }],
      take: FETCH_CAP,
      select: { id: true, clientId: true, appName: true, mailbox: true, scopes: true, ip: true, ts: true, state: true }
    }),
    prisma.wardenGrantFlag.count({ where }),
    prisma.wardenGrantFlag.count({ where: { state: 'NEW' } })
  ]);

  // Group by app (client ID). Scopes are the same for a given app, so take them from the first.
  const byClient = new Map<string, typeof rows>();
  for (const r of rows) {
    const g = byClient.get(r.clientId);
    if (g) g.push(r);
    else byClient.set(r.clientId, [r]);
  }
  const groups = [...byClient.values()]
    .map((rs) => {
      const mailboxes = [...new Set(rs.map((r) => r.mailbox))];
      return {
        clientId: rs[0].clientId,
        appName: rs[0].appName,
        scopes: JSON.parse(rs[0].scopes) as string[],
        mailboxes,
        latest: rs[0].ts,
        count: rs.length
      };
    })
    // Targeted (few mailboxes) first; then most recent.
    .sort((a, b) => a.mailboxes.length - b.mailboxes.length || b.latest.getTime() - a.latest.getTime());

  // ── Add the app's client ID to the allow-list AND mark all its flags benign (ADMIN). The
  //    allow-list is by client ID, which an app cannot forge; future grants from it are
  //    suppressed at the scan. Reversible in Settings → OAuth grants.
  async function allowlistApp(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role !== 'ADMIN') redirect('/grants?error=admin');
    const clientId = String(formData.get('clientId'));
    if (!clientId) redirect('/grants');
    const s = await getSettings(prisma);
    const list = [...new Set([...(s.oauthWatch.allowClientIds ?? []), clientId])];
    await saveSettings(prisma, { oauthWatch: { allowClientIds: list } } as never, u.email);
    const res = await prisma.wardenGrantFlag.updateMany({
      where: { clientId },
      data: { state: 'BENIGN' as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'grant:allowlist', target: clientId, resultCount: res.count, detail: `allow-listed OAuth client; ${res.count} flags cleared` }
    });
    revalidatePath('/grants');
  }

  // ── Set every flag for one app to a state (Investigating / Confirmed / Benign). RESPONDER+.
  async function bulkState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect('/grants?error=role');
    const clientId = String(formData.get('clientId'));
    const next = String(formData.get('state'));
    const res = await prisma.wardenGrantFlag.updateMany({
      where: { clientId },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: `grant:${next}`, target: clientId, resultCount: res.count, detail: `${res.count} flags for one app` }
    });
    revalidatePath('/grants');
  }

  const truncated = rows.length >= FETCH_CAP;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-lg font-semibold">OAuth grants</h1>
        <p className="text-sm text-text-muted">
          New apps granted access that can read or change mail — the persistence a password
          reset does not revoke. Grouped by app: a grant on one mailbox is the targeted-takeover
          shape; a grant on many is usually a rollout. Recognise an app? <strong>Allow-list it</strong>{' '}
          and every flag for it clears and future ones are suppressed.
        </p>
      </header>

      {error === 'admin' && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <strong className="text-danger">Allow-listing an app changes a security setting — ADMIN only.</strong>
        </div>
      )}

      <div className="flex flex-wrap gap-1.5 text-xs">
        {['NEW', 'INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN', 'ALL'].map((s) => (
          <a
            key={s}
            href={`/grants?state=${s}`}
            className={`rounded border px-2.5 py-1 ${s === state ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
          >
            {s === 'ALL' ? 'All' : STATE_LABEL[s]}
            {s === 'NEW' && newCount > 0 ? ` (${newCount})` : ''}
          </a>
        ))}
      </div>

      {groups.length === 0 ? (
        <div className="card text-sm text-text-muted">
          Nothing in this view. If the watch is off, turn it on in{' '}
          <a href="/settings?tab=OAuth+grants" className="underline">Settings &rarr; OAuth grants</a>.
        </div>
      ) : (
        <div className="space-y-2">
          {groups.map((g) => {
            const many = g.mailboxes.length > 1;
            return (
              <div key={g.clientId} className="card space-y-2">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`pill pill-${many ? 'muted' : 'high'}`}>
                        {g.mailboxes.length} {many ? 'mailboxes' : 'mailbox'}
                      </span>
                      <span className="font-medium">{g.appName}</span>
                    </div>
                    <div className="mono mt-0.5 text-xs text-text-muted">client {g.clientId}</div>
                    <div className="mono mt-0.5 text-xs text-text-muted">{g.scopes.join('  ')}</div>
                    <div className="mt-1 text-xs text-text-muted">
                      {many
                        ? 'Authorized across many mailboxes — the shape of an enterprise or ed-tech rollout. If you recognise it, allow-list it.'
                        : 'Authorized on a single mailbox — the shape of a targeted token takeover. Confirm the user recognises it.'}
                      {' · '}latest {fmtTs(g.latest)}
                    </div>
                  </div>

                  {canAct && (
                    <div className="flex flex-col items-end gap-1">
                      {isAdmin && (
                        <form action={allowlistApp}>
                          <input type="hidden" name="clientId" value={g.clientId} />
                          <PendingButton className="btn btn-primary px-2 py-1 text-xs" pending="Allow-listing…">
                            Allow-list this app
                          </PendingButton>
                        </form>
                      )}
                      <div className="flex flex-wrap justify-end gap-1">
                        {(['INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN'] as const).map((st) => (
                          <form key={st} action={bulkState}>
                            <input type="hidden" name="clientId" value={g.clientId} />
                            <input type="hidden" name="state" value={st} />
                            <PendingButton className={`btn px-2 py-1 text-xs ${st === 'CONFIRMED_COMPROMISE' ? 'btn-verdict' : ''}`} pending="…">
                              {STATE_LABEL[st]}{many ? ' all' : ''}
                            </PendingButton>
                          </form>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Clickable: expand to the affected mailboxes, each linking to its account. */}
                {many ? (
                  <details>
                    <summary className="cursor-pointer text-xs text-text-muted">
                      Show the {g.mailboxes.length} mailboxes
                    </summary>
                    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
                      {g.mailboxes.slice(0, 1000).map((mb) => (
                        <a key={mb} href={`/accounts?user=${encodeURIComponent(mb)}`} className="mono text-xs underline">
                          {mb.split('@')[0]}
                        </a>
                      ))}
                      {g.mailboxes.length > 1000 && <span className="text-xs text-text-muted">… +{g.mailboxes.length - 1000} more</span>}
                    </div>
                  </details>
                ) : (
                  <a href={`/accounts?user=${encodeURIComponent(g.mailboxes[0])}`} className="mono text-xs underline">
                    {g.mailboxes[0]}
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}

      <p className="text-xs text-text-muted">
        Read-only detection — Warden never revokes a grant. To stop a confirmed one, revoke the
        app for that mailbox in the Admin console (the user &rarr; Security &rarr; Connected
        applications) or with GAM. A native mail client (Outlook, Apple Mail) legitimately holds
        a mail scope, so a grant is a reason to <em>look</em>, not to alarm.
        {truncated && <> Showing the most recent {FETCH_CAP} flags ({total} total); allow-list the rollouts to clear the backlog.</>}
      </p>
    </div>
  );
}
