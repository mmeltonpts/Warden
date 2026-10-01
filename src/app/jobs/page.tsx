import { redirect } from 'next/navigation';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function JobsPage() {
  const user = await currentUser();
  if (!user) redirect('/login');

  const { domains } = await getSettings(prisma);

  const jobs = await prisma.wardenJob.findMany({
    orderBy: { createdAt: 'desc' },
    take: 100,
    include: { operator: { select: { email: true } } }
  });

  // INCOMPLETE must never read as success: GAM ran but did not finish, so any count on
  // that row is a floor, not a total.
  const cls = (s: string) =>
    s === 'DONE' ? 'pill-ok' : s === 'ERROR' || s === 'REFUSED' ? 'pill-critical'
    : s === 'INCOMPLETE' ? 'pill-high'
    : s === 'RUNNING' ? 'pill-high' : 'pill-medium';

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-lg font-semibold">Jobs</h1>
        <p className="text-sm text-text-muted">
          One job runs at a time — two concurrent full-domain scans compete for the same
          Google API quota.
        </p>
      </header>

      {jobs.length === 0 ? (
        <div className="card text-sm text-text-muted">
          No jobs yet. Start with a <a href="/scope" className="underline">scope</a>.
        </div>
      ) : (
        <div className="overflow-x-auto rounded border">
          <table className="w-full border-collapse bg-bg-surface">
            <thead className="border-b bg-bg-elevated">
              <tr>
                <th className="th w-28">Kind</th>
                <th className="th w-28">Status</th>
                <th className="th w-48">Domain</th>
                <th className="th">Query</th>
                <th className="th w-72">Result</th>
                <th className="th w-32">By</th>
                <th className="th w-40">Created (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id} className="border-b last:border-0">
                  <td className="td">
                    <a href={`/jobs/${j.id}`} className="font-medium hover:underline">{j.kind}</a>
                  </td>
                  <td className="td"><span className={`pill ${cls(j.status)}`}>{j.status}</span></td>
                  {/* The population this job acts on. Not rendered anywhere in the console
                      before now, so a staff sweep and a student sweep looked identical. */}
                  <td className="td mono text-xs">{domains[j.domainKey] ?? j.domainKey}</td>
                  {/* title carries the full query: two scopes differing after character 64
                      were indistinguishable in the list you pick from. */}
                  <td className="td mono text-xs" title={j.query ?? ''}>
                    {(j.query ?? '').slice(0, 64)}
                    {(j.query ?? '').length > 64 ? '…' : ''}
                  </td>
                  <td className="td text-text-muted">{j.summary ?? '—'}</td>
                  <td className="td text-text-muted">{j.operator.email.split('@')[0]}</td>
                  <td className="td mono text-xs text-text-muted">
                    {/* Was headed "Started" while rendering createdAt, with no year and no
                        Z — at 22:00 Eastern in September that prints tomorrow's date. */}
                    {j.createdAt.toISOString().slice(0, 16).replace('T', ' ')}Z
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
