import { redirect } from 'next/navigation';
import { fmtTs } from '@/lib/time';
import { revalidatePath } from 'next/cache';
import { randomBytes } from 'node:crypto';
import { currentUser, hashPassword } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { sendMail, welcomeNotice, passwordResetNotice } from '@/lib/mailer';
import { holdOnce, takeOnce } from '@/lib/onetime';
import { UserPlus, KeyRound, ShieldCheck } from 'lucide-react';

export const dynamic = 'force-dynamic';

const ROLES = ['ANALYST', 'RESPONDER', 'ADMIN'] as const;

const ROLE_HELP: Record<string, string> = {
  ANALYST: 'Read only — scope, triage, view. Cannot sweep.',
  RESPONDER: 'Can execute sweeps after preview and confirmation.',
  ADMIN: 'Everything, plus settings and user management.'
};

export default async function UsersPage({
  searchParams
}: {
  searchParams: Promise<{
    created?: string;
    t?: string;
    error?: string;
    mail?: string;
    mailerr?: string;
  }>;
}) {
  const me = await currentUser();
  if (!me) redirect('/login');
  if (me.role !== 'ADMIN') {
    return <div className="card text-sm">User management requires the ADMIN role.</div>;
  }
  const { created, t, error, mail, mailerr } = await searchParams;
  // Single-use: a refresh must not show the password again.
  const pw = takeOnce(t);

  const MAIL_NOTE: Record<string, string> = {
    sent: 'Notification email delivered.',
    disabled: 'No email sent — notifications are turned off in Settings.',
    no_recipients: 'No email sent — no recipient could be resolved.',
    throttled: 'No email sent — an identical notification went out recently.',
    error: 'The notification email FAILED to send.'
  };

  const users = await prisma.wardenUser.findMany({ orderBy: [{ role: 'desc' }, { email: 'asc' }] });
  const adminCount = users.filter((u) => u.role === 'ADMIN' && !u.disabled).length;

  async function addUser(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');

    const email = String(formData.get('email') ?? '').trim().toLowerCase();
    const displayName = String(formData.get('displayName') ?? '').trim() || email.split('@')[0];
    const role = String(formData.get('role') ?? 'ANALYST');
    if (!email.includes('@')) redirect('/users?error=email');
    if (await prisma.wardenUser.findUnique({ where: { email } })) redirect('/users?error=exists');

    const password = randomBytes(12).toString('base64url');
    await prisma.wardenUser.create({
      data: { email, displayName, role: role as never, passwordHash: await hashPassword(password) }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'user_create', target: email, detail: `role ${role}` }
    });

    // Welcome mail carries the URL and role, never the password — this console can
    // delete mail across the whole district, so its credentials do not travel by email.
    const st = await getSettings(prisma);
    const msg = welcomeNotice(
      { email, displayName, role, invitedBy: u.displayName || u.email },
      st.consoleUrl
    );
    // Report what the send actually did. Swallowing this with `.catch(() => undefined)`
    // meant a new admin simply never heard from us and nobody knew — which is how we
    // found out the relay was rejecting every message at EHLO.
    const mail = await sendMail(st.mail, [email], msg.subject, msg.text, {
      throttleKey: `welcome-${email}`
    }).catch((e) => ({ status: 'error' as const, error: (e as Error).message }));
    const q = new URLSearchParams({
      created: email,
      t: holdOnce(password),
      mail: mail.status,
      ...('error' in mail && mail.error ? { mailerr: mail.error.slice(0, 200) } : {})
    });
    // The token is opaque and single-use; the password itself never enters the URL.
    redirect(`/users?${q.toString()}`);
  }

  async function setRole(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const id = String(formData.get('id'));
    const role = String(formData.get('role'));
    const target = await prisma.wardenUser.findUnique({ where: { id } });
    if (!target) redirect('/users');

    // Never let the last admin demote themselves out of the console.
    if (target.role === 'ADMIN' && role !== 'ADMIN') {
      const others = await prisma.wardenUser.count({
        where: { role: 'ADMIN', disabled: false, id: { not: id } }
      });
      if (others === 0) redirect('/users?error=lastadmin');
    }
    await prisma.wardenUser.update({ where: { id }, data: { role: role as never } });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'user_role', target: target.email, detail: `-> ${role}` }
    });
    revalidatePath('/users');
  }

  async function toggleDisabled(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const id = String(formData.get('id'));
    const target = await prisma.wardenUser.findUnique({ where: { id } });
    if (!target) redirect('/users');
    if (target.id === u.id) redirect('/users?error=self');

    if (!target.disabled && target.role === 'ADMIN') {
      const others = await prisma.wardenUser.count({
        where: { role: 'ADMIN', disabled: false, id: { not: id } }
      });
      if (others === 0) redirect('/users?error=lastadmin');
    }
    await prisma.wardenUser.update({ where: { id }, data: { disabled: !target.disabled } });
    // Kill live sessions immediately — a disabled account with a valid cookie is still in.
    if (!target.disabled) await prisma.wardenSession.deleteMany({ where: { userId: id } });
    await prisma.wardenAudit.create({
      data: {
        operator: u.email,
        action: target.disabled ? 'user_enable' : 'user_disable',
        target: target.email
      }
    });
    revalidatePath('/users');
  }

  async function resetPassword(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const id = String(formData.get('id'));
    const target = await prisma.wardenUser.findUnique({ where: { id } });
    if (!target) redirect('/users');
    const password = randomBytes(12).toString('base64url');
    await prisma.wardenUser.update({
      where: { id },
      data: { passwordHash: await hashPassword(password) }
    });
    await prisma.wardenSession.deleteMany({ where: { userId: id } });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'user_password_reset', target: target.email }
    });
    const st2 = await getSettings(prisma);
    const rmsg = passwordResetNotice(
      { email: target.email, resetBy: u.displayName || u.email },
      st2.consoleUrl
    );
    const mail = await sendMail(st2.mail, [target.email], rmsg.subject, rmsg.text, {
      throttleKey: `reset-${target.email}-${Date.now()}`
    }).catch((e) => ({ status: 'error' as const, error: (e as Error).message }));
    const q = new URLSearchParams({
      created: target.email,
      t: holdOnce(password),
      mail: mail.status,
      ...('error' in mail && mail.error ? { mailerr: mail.error.slice(0, 200) } : {})
    });
    redirect(`/users?${q.toString()}`);
  }

  /**
   * Re-send an invite that never arrived.
   *
   * Only for accounts that have NEVER signed in. The original password was shown once in
   * the browser and is unrecoverable, so a resend has to mint a new one — which would lock
   * out anyone already using the account. The guard is the whole point of a separate action
   * rather than reusing the reset button.
   *
   * Needed when a welcome mail is swallowed by a relay failure nobody can see — before
   * this there was no way to re-issue it from the UI.
   */
  async function resendInvite(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const id = String(formData.get('id'));
    const target = await prisma.wardenUser.findUnique({ where: { id } });
    if (!target) redirect('/users');
    if (target.lastLoginAt) redirect('/users?error=hasloggedin');

    const password = randomBytes(12).toString('base64url');
    await prisma.wardenUser.update({
      where: { id },
      data: { passwordHash: await hashPassword(password) }
    });
    await prisma.wardenAudit.create({
      data: { operator: u.email, action: 'user_reinvite', target: target.email }
    });

    const st = await getSettings(prisma);
    const msg = welcomeNotice(
      {
        email: target.email,
        displayName: target.displayName,
        role: target.role,
        invitedBy: u.displayName || u.email
      },
      st.consoleUrl
    );
    const mail = await sendMail(st.mail, [target.email], msg.subject, msg.text, {
      throttleKey: `reinvite-${target.email}-${Date.now()}`
    }).catch((e) => ({ status: 'error' as const, error: (e as Error).message }));

    const q = new URLSearchParams({
      created: target.email,
      t: holdOnce(password),
      mail: mail.status,
      ...('error' in mail && mail.error ? { mailerr: mail.error.slice(0, 200) } : {})
    });
    redirect(`/users?${q.toString()}`);
  }

  return (
    <div className="max-w-5xl space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Users</h1>
        <p className="text-sm text-text-muted">
          Anyone here can reach a console that deletes mail across every staff and student
          mailbox in the district. Grant ANALYST by default and promote deliberately.
        </p>
      </header>

      {/*
        A consumed or expired token with `created` still in the URL means the admin
        refreshed, navigated back, or left the page open too long. Say so — otherwise the
        card silently disappears and it looks as though the account was never created.
      */}
      {created && !pw && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--warning) / 0.5)' }}>
          <strong className="text-warning">
            The password for {created} has already been shown and cannot be displayed again.
          </strong>
          <p className="mt-1 text-text-muted">
            The account exists and is in the table below. If it was not written down, use
            <strong> Reset password</strong> to issue a new one &mdash; that is cheaper than any
            scheme that would let a password be recovered twice.
          </p>
        </div>
      )}

      {created && pw && (
        <div className="card" style={{ borderColor: 'rgb(var(--success) / 0.4)' }}>
          <div className="flex items-start gap-2 text-sm">
            <KeyRound size={18} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--success))' }} />
            <div>
              <strong>Password for {created}</strong>
              <div className="mono mt-1 rounded bg-bg-elevated px-3 py-2 text-base">{pw}</div>
              <p className="mt-1 text-xs text-text-muted">
                Shown once &mdash; reloading this page will not show it again. It is stored only
                as a bcrypt hash, it is not in this page&rsquo;s URL, and it reaches no log.
                Nobody, including an admin, can recover it later. Send it over something
                other than email.
              </p>
              {mail && (
                <p
                  className="mt-2 text-xs"
                  style={{ color: mail === 'sent' ? undefined : 'rgb(var(--danger))' }}
                >
                  {MAIL_NOTE[mail] ?? `Mail status: ${mail}`}
                  {mailerr && <span className="mono block break-all">{mailerr}</span>}
                  {mail === 'error' && (
                    <span className="mt-1 block text-text-muted">
                      They will not have received anything. Pass them the console URL and this
                      password directly. A <code className="mono">421-4.7.0 … (EHLO)</code> here
                      means this host&rsquo;s public egress IP is not authorised in Admin →
                      Apps → Google Workspace → Gmail → Routing → SMTP relay service.
                    </span>
                  )}
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.4)' }}>
          {error === 'exists' && 'That email already has an account.'}
          {error === 'email' && 'Enter a valid email address.'}
          {error === 'lastadmin' && 'Refused — that would leave no active admin and lock everyone out.'}
          {error === 'self' && 'You cannot disable your own account.'}
          {error === 'hasloggedin' &&
            'Refused — that account has signed in before, so re-inviting would change a password someone is already using. Use Reset password instead.'}
        </div>
      )}

      <form action={addUser} className="card flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Email</span>
          <input name="email" required type="email" placeholder="someone@your-district.org"
                 className="w-64 rounded border bg-bg-elevated px-3 py-1.5 text-sm mono" />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Display name</span>
          <input name="displayName" className="w-48 rounded border bg-bg-elevated px-3 py-1.5 text-sm" />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Role</span>
          <select name="role" defaultValue="ANALYST"
                  className="rounded border bg-bg-elevated px-3 py-1.5 text-sm">
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <button className="btn btn-primary"><UserPlus size={15} /> Add user</button>
      </form>

      <div className="overflow-x-auto rounded border">
        <table className="w-full border-collapse bg-bg-surface">
          <thead className="border-b bg-bg-elevated">
            <tr>
              <th className="th">User</th>
              <th className="th w-44">Role</th>
              <th className="th w-36">Last sign-in</th>
              <th className="th w-56">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b last:border-0">
                <td className="td">
                  <div className="font-medium">
                    {u.displayName}
                    {u.id === me.id && <span className="pill pill-muted ml-2">you</span>}
                    {u.disabled && <span className="pill pill-critical ml-2">disabled</span>}
                  </div>
                  <div className="mono text-xs text-text-muted">{u.email}</div>
                </td>
                <td className="td">
                  <form action={setRole} className="flex items-center gap-1.5">
                    <input type="hidden" name="id" value={u.id} />
                    <select name="role" defaultValue={u.role}
                            className="rounded border bg-bg-elevated px-2 py-1 text-xs">
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button className="btn px-2 py-1 text-xs">Set</button>
                  </form>
                  <div className="mt-1 text-xs text-text-muted">{ROLE_HELP[u.role]}</div>
                </td>
                <td className="td mono text-xs text-text-muted">
                  {u.lastLoginAt ? fmtTs(u.lastLoginAt) : 'never'}
                </td>
                <td className="td">
                  <div className="flex flex-wrap gap-1.5">
                    {!u.lastLoginAt && (
                      <form action={resendInvite}>
                        <input type="hidden" name="id" value={u.id} />
                        <button className="btn btn-primary px-2 py-1 text-xs">Resend invite</button>
                      </form>
                    )}
                    <form action={resetPassword}>
                      <input type="hidden" name="id" value={u.id} />
                      <button className="btn px-2 py-1 text-xs">Reset password</button>
                    </form>
                    {u.id !== me.id && (
                      <form action={toggleDisabled}>
                        <input type="hidden" name="id" value={u.id} />
                        <button className={`btn px-2 py-1 text-xs ${u.disabled ? '' : 'btn-verdict'}`}>
                          {u.disabled ? 'Enable' : 'Disable'}
                        </button>
                      </form>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card flex items-start gap-2 text-sm">
        <ShieldCheck size={16} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--info))' }} />
        <div className="text-text-muted">
          <strong className="text-text-primary">{adminCount} active admin{adminCount === 1 ? '' : 's'}.</strong>{' '}
          Disabling or demoting the last one is refused — a console nobody can administer is
          worse than one with too many admins. Disabling an account also kills its live
          sessions immediately; a valid cookie would otherwise keep working.
        </div>
      </div>
    </div>
  );
}
