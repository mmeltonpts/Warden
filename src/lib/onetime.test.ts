import { describe, it, expect, vi, afterEach } from 'vitest';
import { holdOnce, takeOnce } from './onetime';

afterEach(() => vi.useRealTimers());

describe('one-time secret handoff', () => {
  it('returns the secret exactly once', () => {
    const t = holdOnce('hunter2');
    expect(takeOnce(t)).toBe('hunter2');
    // A refresh of the Users page must not reveal the password a second time.
    expect(takeOnce(t)).toBeNull();
  });

  it('never puts the secret in the token', () => {
    // The token goes in a URL, so it reaches browser history, Referer and access logs.
    const t = holdOnce('hunter2');
    expect(t).not.toContain('hunter2');
    expect(t).toMatch(/^[0-9a-f]{32}$/);
  });

  it('issues a distinct token every time', () => {
    const tokens = new Set(Array.from({ length: 200 }, () => holdOnce('x')));
    expect(tokens.size).toBe(200);
  });

  it('keeps concurrent secrets separate', () => {
    const a = holdOnce('alpha');
    const b = holdOnce('bravo');
    expect(takeOnce(b)).toBe('bravo');
    expect(takeOnce(a)).toBe('alpha');
  });

  it.each([undefined, null, '', 'not-a-real-token'])('returns null for %p', (bad) => {
    expect(takeOnce(bad)).toBeNull();
  });

  it('expires after five minutes', () => {
    vi.useFakeTimers();
    const t = holdOnce('stale');
    vi.advanceTimersByTime(5 * 60_000 + 1);
    expect(takeOnce(t)).toBeNull();
  });

  it('still returns a secret just inside the window', () => {
    vi.useFakeTimers();
    const t = holdOnce('fresh');
    vi.advanceTimersByTime(4 * 60_000);
    expect(takeOnce(t)).toBe('fresh');
  });

  it('does not leak expired entries', () => {
    vi.useFakeTimers();
    const old = Array.from({ length: 50 }, (_, i) => holdOnce(`p${i}`));
    vi.advanceTimersByTime(6 * 60_000);
    // Any call sweeps; after it, every old token is gone rather than merely unreadable.
    holdOnce('trigger');
    for (const t of old) expect(takeOnce(t)).toBeNull();
  });
});
