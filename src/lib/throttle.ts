/**
 * Login brute-force throttle.
 *
 * bcrypt cost 12 plus intranet-only was the only brake on password guessing from an allowed
 * subnet or an insider. This adds a per-account attempt counter with a lockout window.
 *
 * In-memory on purpose: Warden is one Node process on one intranet host (the web app and the
 * worker share it), so a Map pinned to globalThis is enough — and a restart clearing it only
 * ever unlocks a legitimate user sooner, never an attacker who is mid-spray. It is NOT a
 * distributed rate limiter; a multi-host deployment would move this to the database. State
 * pins to globalThis because route handlers do not reliably share a module instance
 * (see instrumentation.ts / CLAUDE.md).
 */
const MAX_FAILS = 5;
const WINDOW_MS = 15 * 60_000;
const LOCKOUT_MS = 15 * 60_000;

interface Entry {
  fails: number[]; // timestamps of recent failures, pruned to the window
  lockedUntil: number;
}

const g = globalThis as unknown as { __wardenLoginThrottle?: Map<string, Entry> };
const store: Map<string, Entry> = (g.__wardenLoginThrottle ??= new Map());

export const LOGIN_MAX_FAILS = MAX_FAILS;
export const LOGIN_LOCKOUT_MINUTES = Math.round(LOCKOUT_MS / 60_000);

/** How long this account stays locked, in ms (0 if not locked). */
export function loginLockRemainingMs(key: string, now: number = Date.now()): number {
  const e = store.get(key.toLowerCase());
  if (!e) return 0;
  return e.lockedUntil > now ? e.lockedUntil - now : 0;
}

/**
 * Record one failed attempt. Returns whether the account is now locked and for how long.
 * Reaching MAX_FAILS inside the window starts the lockout and resets the counter, so the
 * lockout extends only when fresh attempts arrive after it lifts.
 */
export function recordLoginFailure(
  key: string,
  now: number = Date.now()
): { locked: boolean; justLocked: boolean; remainingMs: number } {
  const k = key.toLowerCase();
  const e = store.get(k) ?? { fails: [], lockedUntil: 0 };
  // An attempt made while already locked does not stack; the caller should reject earlier.
  e.fails = e.fails.filter((t) => now - t < WINDOW_MS);
  e.fails.push(now);
  let justLocked = false;
  if (e.fails.length >= MAX_FAILS) {
    e.lockedUntil = now + LOCKOUT_MS;
    e.fails = [];
    justLocked = true;
  }
  store.set(k, e);
  return { locked: e.lockedUntil > now, justLocked, remainingMs: Math.max(0, e.lockedUntil - now) };
}

/** A successful login clears the account's failure state. */
export function clearLoginFailures(key: string): void {
  store.delete(key.toLowerCase());
}
