import { redirect } from 'next/navigation';
import { currentUser, verifyLogin, createSession } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { hasAnyUser, isSetupComplete } from '@/lib/setup';
import {
  loginLockRemainingMs, recordLoginFailure, clearLoginFailures,
  LOGIN_MAX_FAILS, LOGIN_LOCKOUT_MINUTES
} from '@/lib/throttle';

// Always per request: whether any account exists must never be decided at build time.
export const dynamic = 'force-dynamic';

export default async function LoginPage({
  searchParams
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  // A fresh install has nobody to sign in as: send them to claim the console instead.
  if (!(await hasAnyUser(prisma))) redirect('/setup');
  if (await currentUser()) redirect('/risk');
  const { error } = await searchParams;

  async function login(formData: FormData) {
    'use server';
    const email = String(formData.get('email') ?? '').trim().toLowerCase();
    const password = String(formData.get('password') ?? '');
    const key = email || 'unknown';

    // Already locked: reject before touching bcrypt. The lockout itself was audited when it
    // tripped, so a flood of attempts against a locked account does not flood the audit log.
    if (loginLockRemainingMs(key) > 0) redirect('/login?error=locked');

    const user = await verifyLogin(email, password);
    if (!user) {
      const { justLocked } = recordLoginFailure(key);
      await prisma.wardenAudit.create({
        data: {
          operator: key,
          action: justLocked ? 'login_locked' : 'login_failed',
          target: email || '(no email)',
          resultCount: 0,
          detail: justLocked
            ? `locked for ${LOGIN_LOCKOUT_MINUTES} min after ${LOGIN_MAX_FAILS} failed attempts`
            : 'bad credentials'
        }
      }).catch(() => undefined);
      redirect(justLocked ? '/login?error=locked' : '/login?error=1');
    }

    clearLoginFailures(key);
    await prisma.wardenAudit.create({
      data: { operator: user.email, action: 'login', target: user.email, resultCount: 1 }
    }).catch(() => undefined);
    await createSession(user.id);
    redirect(user.role === 'ADMIN' && !(await isSetupComplete(prisma)) ? '/setup' : '/risk');
  }

  return (
    <div className="mx-auto mt-24 w-full max-w-sm">
      <div className="mb-6 text-center">
        <div className="text-lg font-semibold tracking-wide">WARDEN</div>
        <div className="text-xs text-text-muted">phishing incident response</div>
      </div>
      <form action={login} className="card space-y-3">
        {error && (
          <div className="rounded border px-3 py-2 text-sm"
               style={{ background: 'rgb(var(--danger) / 0.12)', color: 'rgb(var(--danger))' }}>
            {error === 'locked'
              ? `Too many failed attempts. This account is locked for ${LOGIN_LOCKOUT_MINUTES} minutes.`
              : 'Invalid credentials'}
          </div>
        )}
        <label className="block text-sm">
          <span className="mb-1 block text-text-muted">Email</span>
          <input name="email" type="email" required autoFocus
                 className="w-full rounded border bg-bg-elevated px-3 py-2 text-sm" />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-text-muted">Password</span>
          <input name="password" type="password" required
                 className="w-full rounded border bg-bg-elevated px-3 py-2 text-sm" />
        </label>
        <button className="btn btn-primary w-full justify-center">Sign in</button>
      </form>
    </div>
  );
}
