/**
 * One-time server-side handoff for a secret that must be displayed exactly once.
 *
 * WHY THIS EXISTS
 *
 * The Users page generated a password, then redirected with it in the query string:
 *
 *     redirect('/users?' + new URLSearchParams({ created: email, pw: password, … }))
 *
 * while the screen it landed on said the password "is stored only as a bcrypt hash —
 * nobody, including an admin, can recover it later". That sentence was false the moment it
 * rendered. A URL reaches browser history, the `Referer` header of any outbound link on
 * that page, the nginx access log, and the Next.js server log — and it stays there for as
 * long as logs are retained. For a console that can trash mail across 7,697 mailboxes, the
 * bootstrap credential being greppable in `/var/log` is not a small thing.
 *
 * Now the URL carries an opaque token and the secret never leaves this process. The token
 * is useless after one read.
 *
 * DELIBERATE LIMITS
 *
 * In-memory, so a restart loses pending secrets. That is the correct trade: the failure
 * mode is "the admin resets the password again", which costs a click. Persisting it would
 * mean writing plaintext credentials to disk to avoid a minor inconvenience.
 *
 * Pinned to `globalThis` because module instances are not reliably shared between route
 * handlers and server actions in this runtime — the same reason the job worker is pinned.
 * A second module instance here would mean the page looks up a token the action stored in
 * a different Map and silently finds nothing.
 */

interface Entry {
  value: string;
  expiresAt: number;
}

const KEY = Symbol.for('warden.onetime');
type Store = Map<string, Entry>;

function store(): Store {
  const g = globalThis as unknown as Record<symbol, Store | undefined>;
  if (!g[KEY]) g[KEY] = new Map<string, Entry>();
  return g[KEY]!;
}

/** Five minutes is far longer than "read the screen" and far shorter than "walk away". */
const TTL_MS = 5 * 60_000;

function sweepExpired(s: Store, now: number) {
  for (const [k, v] of s) if (v.expiresAt <= now) s.delete(k);
}

/**
 * Hold a secret and return the token that retrieves it. The token is safe to put in a URL:
 * it is single-use, short-lived, and reveals nothing on its own.
 */
export function holdOnce(value: string): string {
  const s = store();
  const now = Date.now();
  sweepExpired(s, now);
  // 32 hex chars from the platform CSPRNG. Not a counter, not a timestamp — a token that
  // can be guessed is the same bug wearing a different hat.
  const token = crypto.randomUUID().replace(/-/g, '');
  s.set(token, { value, expiresAt: now + TTL_MS });
  return token;
}

/**
 * Retrieve and destroy. Returns null for an unknown, expired, or already-read token —
 * a refresh of the page must not show the password a second time.
 */
export function takeOnce(token: string | undefined | null): string | null {
  if (!token) return null;
  const s = store();
  const now = Date.now();
  sweepExpired(s, now);
  const hit = s.get(token);
  if (!hit) return null;
  s.delete(token);
  return hit.expiresAt > now ? hit.value : null;
}
