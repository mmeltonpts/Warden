import { describe, it, expect, afterEach } from 'vitest';
import {
  recordLoginFailure, loginLockRemainingMs, clearLoginFailures,
  LOGIN_MAX_FAILS, LOGIN_LOCKOUT_MINUTES
} from './throttle';

// The store is globalThis-pinned, so each test uses its own key and cleans up after.
let n = 0;
const key = () => `t${n}@example.org`;
afterEach(() => clearLoginFailures(key()));

describe('login throttle', () => {
  it('locks only after MAX_FAILS failures and reports the lockout', () => {
    n++;
    const k = key();
    for (let i = 1; i < LOGIN_MAX_FAILS; i++) {
      const r = recordLoginFailure(k, 1000);
      expect(r.locked).toBe(false);
      expect(r.justLocked).toBe(false);
    }
    const last = recordLoginFailure(k, 1000);
    expect(last.justLocked).toBe(true);
    expect(last.locked).toBe(true);
    expect(last.remainingMs).toBe(LOGIN_LOCKOUT_MINUTES * 60_000);
    expect(loginLockRemainingMs(k, 1000)).toBeGreaterThan(0);
    // The lockout lifts once the window passes.
    expect(loginLockRemainingMs(k, 1000 + LOGIN_LOCKOUT_MINUTES * 60_000 + 1)).toBe(0);
  });

  it('does not accumulate failures spread outside the window', () => {
    n++;
    const k = key();
    const windowMs = LOGIN_LOCKOUT_MINUTES * 60_000; // window == lockout duration here
    for (let i = 0; i < LOGIN_MAX_FAILS - 1; i++) recordLoginFailure(k, i * (windowMs + 1));
    // Each prior failure has aged out of the window, so this one does not trip the lock.
    const r = recordLoginFailure(k, LOGIN_MAX_FAILS * (windowMs + 1));
    expect(r.locked).toBe(false);
  });

  it('a success clears the failure state', () => {
    n++;
    const k = key();
    for (let i = 0; i < LOGIN_MAX_FAILS; i++) recordLoginFailure(k, 500);
    expect(loginLockRemainingMs(k, 500)).toBeGreaterThan(0);
    clearLoginFailures(k);
    expect(loginLockRemainingMs(k, 500)).toBe(0);
  });
});
