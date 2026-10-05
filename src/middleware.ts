import { NextRequest, NextResponse } from 'next/server';

/**
 * Fail-closed backstop.
 *
 * Authorization is enforced server-side inside every page and action (currentUser /
 * requireRole), which is the real gate. But that is opt-in per route: a new page that forgets
 * the check would be reachable by anyone on the network. This middleware makes the default
 * "deny": a request with no session cookie never reaches anything but the public paths.
 *
 * It only checks for the PRESENCE of the cookie — it does not validate the session (that needs
 * the database and happens in currentUser). An expired or forged cookie still gets past here
 * and is rejected by the page; what this stops is the no-credentials-at-all case.
 *
 * Runs on the edge runtime, so no database and no Node APIs here.
 */
const SESSION_COOKIE = 'warden_session';

// Reachable without a session: the sign-in and first-run setup pages (and anything under them),
// and the auth endpoints (logout). Everything else requires a cookie.
const PUBLIC_PREFIXES = ['/login', '/setup'];

export function isPublicPath(pathname: string): boolean {
  if (PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + '/'))) return true;
  if (pathname.startsWith('/api/auth/')) return true;
  return false;
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (isPublicPath(pathname)) return NextResponse.next();
  if (req.cookies.get(SESSION_COOKIE)?.value) return NextResponse.next();

  // No session cookie. API routes get a JSON 401 (never an HTML redirect); pages go to /login.
  if (pathname.startsWith('/api/')) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }
  const url = req.nextUrl.clone();
  url.pathname = '/login';
  url.search = '';
  return NextResponse.redirect(url);
}

export const config = {
  // Apply to everything except Next internals and static files (a dotted final segment).
  matcher: ['/((?!_next/static|_next/image|favicon.ico|robots.txt|.*\\.[\\w]+$).*)']
};
