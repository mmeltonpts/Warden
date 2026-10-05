import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { fmtTs } from '@/lib/time';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { PendingButton } from '@/components/PendingButton';

export const dynamic = 'force-dynamic';

/**
 * The forwarding & delegate watch: auto-forwarding, registered forwarding addresses and
 * delegates found across every mailbox. A destination OUTSIDE the district (external) is the
 * BEC/exfil shape and leads the queue; internal items are recorded but land BENIGN. Nothing is
 * removed here — the account-check panel does one-click removal; a human decides.
 */
const STATE_LABEL: Record<string, string> = {
  NEW: 'New',
  INVESTIGATING: 'Investigating',
  CONFIRMED_COMPROMISE: 'Confirmed',
  BENIGN: 'Benign',
  SUPPRESSED: 'Suppressed'
};
const KIND_LABEL: Record<string, string> = {
  forward: 'auto-forward',
  forwardingaddress: 'fwd address',
  delegate: 'delegate'
};

export default async function ForwardingPage({
  searchParams
}: {
  searchParams: Promise<{ view?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { view = 'new' } = await searchParams;

  // Views: new (external & NEW), external (all active external), all (everything active).
  const where =
    view === 'all'
      ? { active: true }
      : view === 'external'
        ? { active: true, external: true }
        : { external: true, state: 'NEW' as never };

  const [items, newCount, externalActive] = await Promise.all([
    prisma.wardenForwardItem.findMany({ where, orderBy: [{ external: 'desc' }, { lastSeen: 'desc' }], take: 400 }),
    prisma.wardenForwardItem.count({ where: { external: true, state: 'NEW' } }),
    prisma.wardenForwardItem.count({ where: { active: true, external: true } })
  ]);

  async function setState(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    if (u.role === 'ANALYST') redirect('/forwarding?error=role');
    const id = String(formData.get('id'));
    const next = String(formData.get('state'));
    await prisma.wardenForwardItem.update({
      where: { id },
      data: { state: next as never, reviewedBy: u.email, reviewedAt: new Date() }
    });
    await prisma.wardenAudit.create({ data: { operator: u.email, action: `forward:${next}`, target: id } });
    revalidatePath('/forwarding');
  }

  const tabs: Array<[string, string]> = [
    ['new', `New external${newCount ? ` (${newCount})` : ''}`],
    ['external', `All external (${externalActive})`],
    ['all', 'All active']
  ];

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Forwarding &amp; delegates</h1>
        <p className="text-sm text-text-muted">
          Auto-forwarding, forwarding addresses and delegates across every mailbox — the BEC
          persistence that survives a password reset. A destination <strong>outside the
          district</strong> is the exfil signal. Removal is one-click on the{' '}
          <span className="text-text-muted">account check</span> panel; this page never removes.
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5 text-xs">
        {tabs.map(([v, label]) => (
          <a
            key={v}
            href={`/forwarding?view=${v}`}
            className={`rounded border px-2.5 py-1 ${v === view ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
          >
            {label}
          </a>
        ))}
      </div>

      {items.length === 0 ? (
        <div className="card text-sm text-text-muted">
          Nothing in this view. If the watch is off, turn it on in{' '}
          <a href="/settings?tab=Forwarding+watch" className="underline">
            Settings &rarr; Forwarding watch
          </a>
          .
        </div>
      ) : (
        <div className="overflow-x-auto rounded border">
          <table className="w-full border-collapse bg-bg-surface">
            <thead className="border-b bg-bg-elevated">
              <tr>
                <th className="th w-24">Where</th>
                <th className="th">Mailbox</th>
                <th className="th">Destination</th>
                <th className="th">Why</th>
                <th className="th w-36">Seen</th>
                <th className="th w-52">Triage</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => {
                const reasons: string[] = JSON.parse(it.reasons);
                return (
                  <tr key={it.id} className="border-b last:border-0 align-top">
                    <td className="td">
                      <span className={`pill ${it.external ? 'pill-high' : 'pill-muted'}`}>
                        {it.external ? 'external' : 'internal'}
                      </span>
                      <div className="mt-0.5 text-xs text-text-muted">{KIND_LABEL[it.kind] ?? it.kind}</div>
                    </td>
                    <td className="td mono">{it.mailbox.split('@')[0]}</td>
                    <td className="td mono text-xs">{it.target}</td>
                    <td className="td">
                      <ul className="space-y-0.5 text-xs text-text-muted">
                        {reasons.map((r, i) => (
                          <li key={i}>&bull; {r}</li>
                        ))}
                      </ul>
                    </td>
                    <td className="td text-xs text-text-muted">
                      <div>first {fmtTs(it.firstSeen)}</div>
                      {!it.active && <div className="text-text-muted">removed — {fmtTs(it.lastSeen)}</div>}
                    </td>
                    <td className="td">
                      <div className="flex flex-wrap gap-1">
                        {(['INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN'] as const).map((st) => (
                          <form key={st} action={setState}>
                            <input type="hidden" name="id" value={it.id} />
                            <input type="hidden" name="state" value={st} />
                            <PendingButton
                              className={`btn px-2 py-1 text-xs ${st === 'CONFIRMED_COMPROMISE' ? 'btn-verdict' : ''}`}
                              pending="…"
                              disabled={it.state === st || user.role === 'ANALYST'}
                            >
                              {STATE_LABEL[st]}
                            </PendingButton>
                          </form>
                        ))}
                      </div>
                      <div className="mt-1 text-xs text-text-muted">
                        <a href={`/accounts?user=${encodeURIComponent(it.mailbox)}`} className="underline">
                          account
                        </a>
                        {it.reviewedBy && (
                          <>
                            {' '}
                            &middot; {STATE_LABEL[it.state]} &middot; {it.reviewedBy.split('@')[0]}
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
        Read-only detection. An external forward or delegate survives a password reset, so
        removing it is part of evicting a takeover — but a shared role mailbox or an assistant
        who manages a principal&rsquo;s mail is legitimate. Confirm with the person before
        removing.
      </p>
    </div>
  );
}
