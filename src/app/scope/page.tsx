import { redirect } from 'next/navigation';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { AlertTriangle } from 'lucide-react';

export const dynamic = 'force-dynamic';

/**
 * Scope is read-only and always the first step. A sweep can only be created from a
 * completed scope (see /jobs/[id]), so nobody can trash mail they have not looked at.
 */
export default async function ScopePage({
  searchParams
}: {
  searchParams: Promise<{ error?: string; query?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  // Rendered, not merely redirected to. The action has always redirected here on an empty
  // query and this page never accepted searchParams, so the failure was invisible.
  const { error, query: prefill } = await searchParams;

  const s = await getSettings(prisma);
  const iocs = await prisma.wardenIoc.findMany({
    where: { kind: 'LURE_STRING' },
    orderBy: { addedAt: 'desc' },
    take: 12
  });
  const recent = await prisma.wardenJob.findMany({
    where: { kind: 'SCOPE' },
    orderBy: { createdAt: 'desc' },
    take: 8,
    include: { operator: { select: { email: true } } }
  });

  async function createScope(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u) redirect('/login');
    const query = String(formData.get('query') ?? '').trim();
    const domainKey = String(formData.get('domainKey') ?? 'staff');
    if (!query) redirect('/scope?error=empty');
    const job = await prisma.wardenJob.create({
      data: { kind: 'SCOPE', operatorId: u.id, domainKey, query }
    });
    redirect(`/jobs/${job.id}`);
  }

  return (
    <div className="max-w-4xl space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Scope</h1>
        <p className="text-sm text-text-muted">
          Read-only. Counts and enumerates matching mail so you can see what a sweep would
          touch before anything is trashed.
        </p>
      </header>

      {error === 'empty' && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <strong className="text-danger">
            Nothing was run &mdash; the query was empty.
          </strong>
        </div>
      )}

      <form action={createScope} className="card space-y-3">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Gmail query</span>
          <textarea
            name="query"
            rows={3}
            required
            defaultValue={prefill ?? ''}
            placeholder={'"Download Transcript Record PDF" in:anywhere newer_than:30d'}
            className="w-full rounded border bg-bg-elevated px-3 py-2 text-sm mono"
          />
        </label>

        <div className="flex items-end gap-4">
          <label className="text-sm">
            <span className="mb-1 block font-medium">Domain</span>
            <select
              name="domainKey"
              className="rounded border bg-bg-elevated px-3 py-1.5 text-sm mono"
            >
              <option value="staff">{s.domains.staff}</option>
              <option value="students">{s.domains.students}</option>
            </select>
          </label>
          <button className="btn btn-primary">Run scope</button>
          <span className="text-xs text-text-muted">
            A full-domain scan takes 8–15 minutes.
          </span>
        </div>
      </form>

      <div className="card space-y-2 text-sm">
        <div className="flex items-start gap-2">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--warning))' }} />
          <div>
            <strong>Scope on lure text, not the payload domain.</strong>
            <p className="mt-1 text-text-muted">
              Gmail&rsquo;s index is tokenised and will not reliably match a bare domain inside
              a URL — a scan for <code className="mono">downloaddocc.com</code> returned zero hits
              for a domain provably present in message bodies. Use a distinctive phrase, then
              confirm payloads by reading bodies.
            </p>
          </div>
        </div>
      </div>

      {iocs.length > 0 && (
        <div className="card">
          <h2 className="mb-2 text-sm font-medium">Known lure strings</h2>
          <div className="flex flex-wrap gap-1.5">
            {iocs.map((i) => (
              <span key={i.id} className="pill pill-muted mono" title={i.notes ?? undefined}>
                {i.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {recent.length > 0 && (
        <div>
          <h2 className="mb-2 text-sm font-medium">Recent scopes</h2>
          <div className="overflow-x-auto rounded border">
            <table className="w-full border-collapse bg-bg-surface">
              <thead className="border-b bg-bg-elevated">
                <tr>
                  <th className="th">Query</th>
                  <th className="th w-28">Status</th>
                  <th className="th w-64">Result</th>
                  <th className="th w-40">By</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((j) => (
                  <tr key={j.id} className="border-b last:border-0">
                    <td className="td mono">
                      <a href={`/jobs/${j.id}`} className="hover:underline">
                        {(j.query ?? '').slice(0, 70)}
                      </a>
                    </td>
                    <td className="td">
                      <span
                        className={`pill ${
                          j.status === 'DONE' ? 'pill-ok'
                            : j.status === 'ERROR' || j.status === 'REFUSED' ? 'pill-critical'
                            : j.status === 'INCOMPLETE' ? 'pill-high'
                            : 'pill-medium'
                        }`}
                      >
                        {j.status}
                      </span>
                    </td>
                    <td className="td text-text-muted">{j.summary ?? '—'}</td>
                    <td className="td text-text-muted">{j.operator.email.split('@')[0]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
