/**
 * Session auth. bcryptjs + an opaque session row; no JWTs, nothing in localStorage.
 *
 * Role gates are enforced server-side on every mutating route. The UI hides what a
 * role cannot do, but hiding is not enforcement — anyone reaching this app can delete
 * mail in every mailbox in the district.
 */
import { cookies, headers } from 'next/headers';
import bcrypt from 'bcryptjs';
import { prisma } from './db';

export const SESSION_COOKIE = 'warden_session';
const SESSION_DAYS = 7;

/**
 * A `Secure` cookie is never sent over plain HTTP, so marking it Secure while the
 * console is served on http:// silently logs the user out on every navigation.
 *
 * So follow the protocol the browser actually used, as nginx reports it in
 * X-Forwarded-Proto. Over HTTPS the cookie is Secure; over plain HTTP it cannot be. This
 * used to be an .env flag that had to be flipped by hand after TLS went in — exactly the
 * kind of step that is forgotten, in either direction.
 */
async function cookieSecure(): Promise<boolean> {
  const proto = (await headers()).get('x-forwarded-proto');
  if (proto) return proto.split(',')[0].trim() === 'https';
  return process.env.NODE_ENV === 'production';
}

export type Role = 'ANALYST' | 'RESPONDER' | 'ADMIN';

const RANK: Record<Role, number> = { ANALYST: 1, RESPONDER: 2, ADMIN: 3 };

export async function hashPassword(pw: string) {
  return bcrypt.hash(pw, 12);
}

export async function verifyLogin(email: string, password: string) {
  const user = await prisma.wardenUser.findUnique({ where: { email: email.toLowerCase() } });
  if (!user || user.disabled) return null;
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return null;
  await prisma.wardenUser.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  return user;
}

export async function createSession(userId: string) {
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400_000);
  const s = await prisma.wardenSession.create({ data: { userId, expiresAt } });
  const jar = await cookies();
  jar.set(SESSION_COOKIE, s.id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: await cookieSecure(),
    path: '/',
    expires: expiresAt
  });
  return s;
}

export async function destroySession() {
  const jar = await cookies();
  const id = jar.get(SESSION_COOKIE)?.value;
  if (id) await prisma.wardenSession.delete({ where: { id } }).catch(() => undefined);
  jar.delete(SESSION_COOKIE);
}

export async function currentUser() {
  const jar = await cookies();
  const id = jar.get(SESSION_COOKIE)?.value;
  if (!id) return null;
  const s = await prisma.wardenSession.findUnique({ where: { id }, include: { user: true } });
  if (!s || s.expiresAt < new Date() || s.user.disabled) return null;
  return s.user;
}

export async function requireUser() {
  const u = await currentUser();
  if (!u) throw new Error('UNAUTHENTICATED');
  return u;
}

export async function requireRole(min: Role) {
  const u = await requireUser();
  if (RANK[u.role as Role] < RANK[min]) throw new Error('FORBIDDEN');
  return u;
}
