import { redirect } from 'next/navigation';
import { fmtTs } from '@/lib/time';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';

export const dynamic = 'force-dynamic';

const PAGE = 300;

/**
 * Actions worth isolating when reconstructing an incident. Defaults to these rather than
 * to everything: every triage click writes a row, so on a busy night the sweeps — the only
 * rows the schema calls unreconstructable — scroll off the end of a 300-row page within
 * days, and there was no filter to get them back.
 */
const CONSEQUENTIAL = [
  'sweep',
  'sweep_selected',
  'sweep_refused',
  'verify',
  'scope',
  'account_check',
  'account_check_bulk',
  'settings_update',
  'job_cancelled',
  'alert_mirror_FAILED',
  // Privilege and access changes, and failed sign-ins — the rows an incident reviewer needs
  // first. Granting ADMIN or resetting a password must not hide under "Everything".
  'user_create',
  'user_role',
  'user_password_reset',
  'user_reinvite',
  'user_disable',
  'user_enable',
  'login_failed',
  'login_locked',
  // Every email Warden sends to a person: the staff "was this you?" verification and its
  // outcome, and the handbook notice sent to a student. Here so they show in the default
  // view, not only under "all".
  'signin_verify_sent',
  'signin_verify_denied',
  'signin_verify_hidden',
  'student_vpn_notice',
  // Account response actions — suspend, reset, deprovision, sign-out, un-suspend.
  'user_suspend',
  'user_unsuspend',
  'user_reset',
  'user_deprovision',
  'user_signout'
];

const VIEWS: Array<{ key: string; label: string }> = [
  { key: 'consequential', label: 'Sweeps & changes' },
  { key: 'all', label: 'Everything' }
];

export default async function AuditPage({
  searchParams
}: {
  searchParams: Promise<{ view?: string; operator?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  const { view = 'consequential', operator } = await searchParams;

  const where = {
    // Quarantine reviews name recipients and subjects of mail that was never delivered.
    ...(user.role === 'ADMIN' ? {} : { NOT: { action: { startsWith: 'quarantine' } } }),
    ...(view === 'all' ? {} : { action: { in: CONSEQUENTIAL } }),
    ...(operator ? { operator } : {})
  };

  const [rows, total, operators] = await Promise.all([
    prisma.wardenAudit.findMany({ where, orderBy: { ts: 'desc' }, take: PAGE }),
    prisma.wardenAudit.count({ where }),
    prisma.wardenAudit.findMany({ where: user.role === 'ADMIN' ? {} : { NOT: { action: { startsWith: 'quarantine' } } }, select: { operator: true }, distinct: ['operator'], take: 25 })
  ]);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-lg font-semibold">Audit</h1>
        <p className="text-sm text-text-muted">
          Append-only. Mail a sweep touches is recoverable from Trash; the record of who
          swept is not reconstructable after the fact.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        {VIEWS.map((v) => (
          <a
            key={v.key}
            href={`/audit?view=${v.key}${operator ? `&operator=${encodeURIComponent(operator)}` : ''}`}
            className={`rounded border px-2.5 py-1 ${
              v.key === view ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
            }`}
          >
            {v.label}
          </a>
        ))}
        <span className="ml-2 text-text-muted">Operator:</span>
        <a
          href={`/audit?view=${view}`}
          className={`rounded border px-2.5 py-1 ${!operator ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
        >
          anyone
        </a>
        {operators.map((o) => (
          <a
            key={o.operator}
            href={`/audit?view=${view}&operator=${encodeURIComponent(o.operator)}`}
            className={`rounded border px-2.5 py-1 ${
              operator === o.operator ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
            }`}
          >
            {o.operator.split('@')[0]}
          </a>
        ))}
      </div>

      <p className="text-xs text-text-muted">
        {total.toLocaleString()} matching{' '}
        {total > PAGE && <>&mdash; showing the most recent {PAGE}</>}
        {view === 'consequential' && (
          <> &middot; triage verdicts are hidden here; use &ldquo;Everything&rdquo; to see them.</>
        )}
      </p>

      <div className="overflow-x-auto rounded border">
        <table className="w-full border-collapse bg-bg-surface">
          <thead className="border-b bg-bg-elevated">
            <tr>
              <th className="th w-40">When</th>
              <th className="th w-32">Operator</th>
              <th className="th w-36">Action</th>
              {/* The swept DOMAIN lives in `target`, and this column did not exist — so the
                  permanent record of a sweep did not say whether it hit 1,360 staff
                  mailboxes or 6,300 student ones. */}
              <th className="th w-52">Target</th>
              <th className="th">Query</th>
              <th className="th w-24">Count</th>
              <th className="th w-64">Detail</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b last:border-0 align-top">
                <td className="td mono text-xs text-text-muted">
                  {fmtTs(r.ts)}
                </td>
                <td className="td text-xs">{r.operator.split('@')[0]}</td>
                <td className="td">
                  <span
                    className={`pill ${
                      r.action === 'sweep'
                        ? 'pill-critical'
                        : r.action === 'sweep_refused' || r.action.endsWith('FAILED')
                          ? 'pill-high'
                          : r.action === 'verify'
                            ? r.verified
                              ? 'pill-ok'
                              : 'pill-high'
                            : 'pill-muted'
                    }`}
                  >
                    {r.action}
                  </span>
                </td>
                <td className="td mono text-xs break-all">{r.target ?? '—'}</td>
                {/* Full query, wrapped. It was truncated to 60 characters with no way to
                    see the rest — and the part cut off is the protective suffix, which is
                    exactly what proves responders were excluded from a sweep. */}
                <td className="td mono text-xs break-all">{r.query ?? '—'}</td>
                <td className="td text-xs">
                  {r.resultCount ?? '—'}
                  {r.resultCount !== null && (
                    <div className="text-text-muted">
                      {r.action === 'sweep'
                        ? 'messages'
                        : r.action === 'scope' || r.action === 'verify'
                          ? 'messages'
                          : r.action === 'account_check'
                            ? 'findings'
                            : 'records'}
                    </div>
                  )}
                </td>
                <td className="td text-xs text-text-muted break-words">{r.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {rows.length === 0 && (
        <div className="card text-sm text-text-muted">
          No matching entries. {view === 'consequential' && 'Try “Everything”.'}
        </div>
      )}

      <p className="text-xs text-text-muted">
        Sign-in and sign-out are not recorded here, and this table is an ordinary database
        table &mdash; append-only by convention, not enforced by the database. Anyone with
        Postgres access on the host can alter it.
      </p>
    </div>
  );
}
