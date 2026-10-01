import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { sendMail } from '@/lib/mailer';
import { PendingButton } from '@/components/PendingButton';

export const dynamic = 'force-dynamic';

const STATE_PILL: Record<string, string> = {
  SENT: 'pill', CONFIRMED_YES: 'pill-ok', DENIED: 'pill-critical', HIDDEN: 'pill-critical', EXPIRED: 'pill', ERROR: 'pill-high'
};
const fmt = (d: Date | null) => (d ? d.toISOString().replace('T', ' ').slice(0, 16) : '');
const parseChecks = (j: string | null): Array<{ at: string; label: string; detail: string }> => {
  try { return j ? JSON.parse(j) : []; } catch { return []; }
};

// ── server actions (module scope; they read everything they need from the form) ──
async function sendNotice(formData: FormData) {
  'use server';
  const u = await currentUser();
  if (!u || u.role === 'ANALYST') redirect('/login');
  const id = String(formData.get('id') ?? '');
  const back = String(formData.get('back') ?? '/verify?tab=students');
  const n = await prisma.wardenStudentVpnNotice.findUnique({ where: { id } });
  if (!n || n.state !== 'QUEUED') redirect(back);
  const cfg = await getSettings(prisma);
  const when = n.signInTs.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const body = cfg.studentVpn.noticeBody.replaceAll('{when}', when).replaceAll('{building}', n.building ?? 'School');
  const res = await sendMail(cfg.mail, [n.student], cfg.studentVpn.noticeSubject, body, {
    throttleKey: `svpn-${n.id}`, ...(n.adminEmail ? { replyTo: n.adminEmail } : {})
  });
  await prisma.wardenStudentVpnNotice.update({
    where: { id },
    data: {
      state: res.status === 'sent' ? 'SENT' : 'QUEUED',
      reviewedBy: u.email, reviewedAt: new Date(),
      notes: res.status === 'sent' ? 'handbook notice sent' : `send failed: ${res.status}${res.error ? ` ${res.error}` : ''}`
    }
  });
  await prisma.wardenAudit.create({
    data: { operator: u.email, action: 'student_vpn_notice', target: n.student, detail: res.status === 'sent' ? 'handbook notice sent' : `send ${res.status}` }
  }).catch(() => undefined);
  revalidatePath('/verify');
  redirect(back);
}

async function dismissNotice(formData: FormData) {
  'use server';
  const u = await currentUser();
  if (!u || u.role === 'ANALYST') redirect('/login');
  const id = String(formData.get('id') ?? '');
  const back = String(formData.get('back') ?? '/verify?tab=students');
  await prisma.wardenStudentVpnNotice.update({
    where: { id }, data: { state: 'DISMISSED', reviewedBy: u.email, reviewedAt: new Date(), notes: 'not a violation' }
  }).catch(() => undefined);
  await prisma.wardenAudit.create({ data: { operator: u.email, action: 'student_vpn_dismiss', target: id } }).catch(() => undefined);
  revalidatePath('/verify');
  redirect(back);
}

async function closeVerify(formData: FormData) {
  'use server';
  const u = await currentUser();
  if (!u || u.role === 'ANALYST') redirect('/login');
  const id = String(formData.get('id') ?? '');
  await prisma.wardenSignInVerify.update({
    where: { id }, data: { state: 'EXPIRED', closedAt: new Date(), notes: `closed by ${u.email}` }
  }).catch(() => undefined);
  revalidatePath('/verify');
  redirect('/verify?tab=staff');
}

export default async function VerifyPage({
  searchParams
}: {
  searchParams: Promise<{ tab?: string; building?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  if (user.role === 'ANALYST') return <div className="card text-sm">Verification is available to RESPONDER and ADMIN.</div>;

  const { tab: tabParam, building } = await searchParams;
  const tab = tabParam === 'students' ? 'students' : 'staff';
  const s = await getSettings(prisma);

  const [openVerify, openStudents] = await Promise.all([
    prisma.wardenSignInVerify.count({ where: { state: 'SENT' } }),
    prisma.wardenStudentVpnNotice.count({ where: { state: 'QUEUED' } })
  ]);

  const tabLink = (k: string, label: string, n: number) => (
    <a href={`/verify?tab=${k}`} className={`rounded border px-2.5 py-1 ${tab === k ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}>
      {label} {n > 0 && <span className="text-text-muted">({n})</span>}
    </a>
  );

  // ── staff data ────────────────────────────────────────────────────────────────
  const vRows = tab === 'staff' ? await prisma.wardenSignInVerify.findMany({ orderBy: { sentAt: 'desc' }, take: 200 }) : [];
  const vOpen = vRows.filter((r) => r.state === 'SENT');
  const vClosed = vRows.filter((r) => r.state !== 'SENT');

  // ── student data ───────────────────────────────────────────────────────────────
  const buildings = tab === 'students'
    ? await prisma.wardenStudentVpnNotice.findMany({ where: { state: 'QUEUED' }, distinct: ['building'], select: { building: true } })
    : [];
  const queued = tab === 'students'
    ? await prisma.wardenStudentVpnNotice.findMany({ where: { state: 'QUEUED', ...(building ? { building } : {}) }, orderBy: [{ building: 'asc' }, { createdAt: 'desc' }], take: 300 })
    : [];
  const handled = tab === 'students'
    ? await prisma.wardenStudentVpnNotice.findMany({ where: { state: { in: ['SENT', 'DISMISSED'] } }, orderBy: { reviewedAt: 'desc' }, take: 40 })
    : [];
  const back = `/verify?tab=students${building ? `&building=${encodeURIComponent(building)}` : ''}`;

  return (
    <div className="max-w-5xl space-y-4">
      <header>
        <h1 className="text-lg font-semibold">Verify</h1>
        <p className="text-sm text-text-muted">Human-in-the-loop follow-up for risky sign-ins. Warden asks; it never suspends or resets anything itself.</p>
      </header>

      <div className="flex flex-wrap gap-1.5 text-xs">
        {tabLink('staff', 'Staff verification', openVerify)}
        {tabLink('students', 'Student VPN', openStudents)}
      </div>

      {tab === 'staff' && (
        <div className="space-y-4">
          {!s.signinVerify.enabled && (
            <div className="card text-sm text-text-muted">
              Staff verification is off. Turn it on under <a href="/settings?tab=Verify" className="underline">Settings → Verify</a> (you also need a reply mailbox and email notifications on).
            </div>
          )}
          {vRows.length === 0 ? (
            <p className="text-sm text-text-muted">Nothing yet. A verification email is sent after a risky VPN or foreign staff sign-in.</p>
          ) : (
            <>
              {vOpen.length > 0 && (
                <section>
                  <h2 className="mb-1 text-sm font-semibold">Waiting ({vOpen.length})</h2>
                  <div className="space-y-2">
                    {vOpen.map((v) => {
                      const checks = parseChecks(v.checks);
                      return (
                        <div key={v.id} className="card text-sm">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="pill">SENT</span>
                            <strong>{v.mailbox}</strong>
                            <span className="text-xs text-text-muted">signed in {fmt(v.signInTs)} UTC · {v.netOrg ?? '?'}{v.geo ? ` (${v.geo})` : ''} · emailed {fmt(v.sentAt)}</span>
                          </div>
                          {checks.length > 0 && (
                            <ul className="mt-1 text-xs text-text-muted">
                              {checks.slice(-4).map((c, i) => <li key={i}>· {c.label}: {c.detail}</li>)}
                            </ul>
                          )}
                          <form action={closeVerify} className="mt-2">
                            <input type="hidden" name="id" value={v.id} />
                            <PendingButton className="btn text-xs" pending="Closing…">Close (handled another way)</PendingButton>
                          </form>
                        </div>
                      );
                    })}
                  </div>
                </section>
              )}
              <section>
                <h2 className="mb-1 text-sm font-semibold">Resolved</h2>
                <table className="w-full border-collapse text-sm">
                  <thead><tr className="border-b text-left"><th className="th">Outcome</th><th className="th">Mailbox</th><th className="th">Network</th><th className="th">Sign-in</th><th className="th">Detail</th></tr></thead>
                  <tbody>
                    {vClosed.slice(0, 100).map((v) => (
                      <tr key={v.id} className={`border-b align-top ${v.state === 'DENIED' || v.state === 'HIDDEN' ? 'font-medium' : ''}`}>
                        <td className="td"><span className={`pill ${STATE_PILL[v.state] ?? 'pill'}`}>{v.state}</span></td>
                        <td className="td">{v.mailbox}</td>
                        <td className="td text-xs">{v.netOrg ?? '?'}{v.geo ? ` (${v.geo})` : ''}</td>
                        <td className="td text-xs">{fmt(v.signInTs)}</td>
                        <td className="td text-xs text-text-muted">{v.replyExcerpt ?? v.filterFound ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            </>
          )}
        </div>
      )}

      {tab === 'students' && (
        <div className="space-y-4">
          {!s.studentVpn.enabled && (
            <div className="card text-sm text-text-muted">
              Student VPN queueing is off. Turn it on under <a href="/settings?tab=Student notices" className="underline">Settings → Student notices</a> (needs student sign-in scanning on).
            </div>
          )}
          <p className="text-xs text-text-muted">
            Each row is a student account seen signing in through a VPN or privacy relay. Review it and send the handbook
            notice, or dismiss it — an iPhone&apos;s default Private Relay looks the same as a VPN here, so judgement is yours.
            {!s.mail.enabled && ' Email notifications are off, so notices cannot be sent yet.'}
          </p>

          {buildings.length > 1 && (
            <div className="flex flex-wrap gap-1.5 text-xs">
              <a href="/verify?tab=students" className={`rounded border px-2 py-0.5 ${!building ? 'bg-bg-elevated' : 'text-text-muted'}`}>All</a>
              {buildings.map((b) => b.building && (
                <a key={b.building} href={`/verify?tab=students&building=${encodeURIComponent(b.building)}`}
                   className={`rounded border px-2 py-0.5 ${building === b.building ? 'bg-bg-elevated' : 'text-text-muted'}`}>{b.building}</a>
              ))}
            </div>
          )}

          {queued.length === 0 ? (
            <p className="text-sm text-text-muted">Nothing in the queue.</p>
          ) : (
            <div className="space-y-2">
              {queued.map((n) => (
                <div key={n.id} className="card flex flex-wrap items-center justify-between gap-2 text-sm">
                  <div>
                    <strong>{n.student}</strong>
                    <div className="text-xs text-text-muted">
                      {fmt(n.signInTs)} UTC · {n.netOrg ?? 'VPN'}{n.geo ? ` (${n.geo})` : ''}
                      {' · '}{n.building ?? n.ouPath ?? 'unknown building'}{n.schoolHours ? ' · during school hours' : ''}
                      {n.adminEmail ? ` · routed to ${n.adminEmail}` : ' · no building admin matched'}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <form action={sendNotice}>
                      <input type="hidden" name="id" value={n.id} />
                      <input type="hidden" name="back" value={back} />
                      <PendingButton className="btn btn-primary text-xs" pending="Sending…" disabled={!s.mail.enabled}>Send handbook notice</PendingButton>
                    </form>
                    <form action={dismissNotice}>
                      <input type="hidden" name="id" value={n.id} />
                      <input type="hidden" name="back" value={back} />
                      <PendingButton className="btn text-xs" pending="…">Dismiss</PendingButton>
                    </form>
                  </div>
                </div>
              ))}
            </div>
          )}

          {handled.length > 0 && (
            <section>
              <h2 className="mb-1 text-sm font-semibold">Recently handled</h2>
              <table className="w-full border-collapse text-sm">
                <thead><tr className="border-b text-left"><th className="th">Result</th><th className="th">Student</th><th className="th">Building</th><th className="th">By</th><th className="th">When</th></tr></thead>
                <tbody>
                  {handled.map((n) => (
                    <tr key={n.id} className="border-b">
                      <td className="td"><span className={`pill ${n.state === 'SENT' ? 'pill-ok' : 'pill'}`}>{n.state === 'SENT' ? 'notice sent' : 'dismissed'}</span></td>
                      <td className="td">{n.student}</td>
                      <td className="td text-xs">{n.building ?? ''}</td>
                      <td className="td text-xs text-text-muted">{n.reviewedBy ?? ''}</td>
                      <td className="td text-xs text-text-muted">{fmt(n.reviewedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
