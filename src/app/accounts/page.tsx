import { redirect } from 'next/navigation';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';

export const dynamic = 'force-dynamic';

/**
 * Per-mailbox compromise indicators. This is the check that found both real takeovers:
 * filters, forwarding, delegates, app passwords, OAuth scopes.
 */
export default async function AccountsPage({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  // The input is type="text", so `jsmith` satisfies `required` and then fails the @ check.
  // That redirect had nowhere to land until now.
  const { error } = await searchParams;

  const recent = await prisma.wardenJob.findMany({
    where: { kind: 'ACCOUNT_CHECK' },
    orderBy: { createdAt: 'desc' },
    take: 25,
    include: { operator: { select: { email: true } } }
  });

  async function check(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const raw = String(formData.get('user') ?? '').trim().toLowerCase();
    if (!raw.includes('@')) redirect('/accounts?error=email');
    const job = await prisma.wardenJob.create({
      data: {
        kind: 'ACCOUNT_CHECK', operatorId: u.id, domainKey: 'staff',
        argsJson: JSON.stringify({ user: raw }), query: raw
      }
    });
    redirect(`/jobs/${job.id}`);
  }

  return (
    <div className="max-w-4xl space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Account check</h1>
        <p className="text-sm text-text-muted">
          Filters, forwarding, delegates, app passwords and OAuth scopes for one mailbox.
          Read-only.
        </p>
      </header>

      {error === 'email' && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <strong className="text-danger">
            Nothing was run &mdash; enter a full email address, not just the username.
          </strong>
        </div>
      )}

      <form action={check} className="card flex items-end gap-3">
        <label className="flex-1 text-sm">
          <span className="mb-1 block font-medium">Mailbox</span>
          <input
            name="user"
            required
            placeholder="someone@your-district.org"
            className="w-full rounded border bg-bg-elevated px-3 py-1.5 text-sm mono"
          />
        </label>
        <button className="btn btn-primary">Run check</button>
      </form>

      <div className="card text-sm">
        <strong>What a hit means.</strong>
        <p className="mt-1 text-text-muted">
          A <code className="mono">trash + markread</code> filter is the highest-fidelity
          compromise signal there is — across 31 risky-action events in September it fired
          once, on the one account genuinely taken over. Forwarding to an external address
          is exfiltration. Neither survives a password reset on its own.
        </p>
      </div>

      {recent.length > 0 && (
        <div className="overflow-x-auto rounded border">
          <table className="w-full border-collapse bg-bg-surface">
            <thead className="border-b bg-bg-elevated">
              <tr>
                <th className="th">Mailbox</th>
                <th className="th w-24">Status</th>
                <th className="th">Finding</th>
                <th className="th w-32">By</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((j) => {
                // Only a completed check can be clean. doAccountCheck now returns
                // INCONCLUSIVE when any of the six sub-checks failed, and an INCOMPLETE
                // job never earns a green pill.
                const clean = j.status === 'DONE' && (j.summary ?? '').startsWith('clean');
                return (
                  <tr key={j.id} className="border-b last:border-0">
                    <td className="td mono">
                      <a href={`/jobs/${j.id}`} className="hover:underline">{j.query}</a>
                    </td>
                    <td className="td">
                      <span
                        className={`pill ${
                          clean
                            ? 'pill-ok'
                            : j.status === 'DONE'
                              ? 'pill-critical'
                              : j.status === 'INCOMPLETE' || j.status === 'ERROR'
                                ? 'pill-high'
                                : 'pill-medium'
                        }`}
                      >
                        {j.status}
                      </span>
                    </td>
                    <td className="td text-text-muted">{j.summary ?? '—'}</td>
                    <td className="td text-text-muted">{j.operator.email.split('@')[0]}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
