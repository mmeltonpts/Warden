import { describe, it, expect } from 'vitest';
import { isPublicPath } from './middleware';

describe('fail-closed middleware: public paths', () => {
  it('allows the sign-in, setup, and auth paths without a session', () => {
    expect(isPublicPath('/login')).toBe(true);
    expect(isPublicPath('/setup')).toBe(true);
    expect(isPublicPath('/setup/anything')).toBe(true);
    expect(isPublicPath('/api/auth/logout')).toBe(true);
  });

  it('requires a session for every console route, including pulse', () => {
    for (const p of ['/', '/risk', '/jobs/abc', '/accounts', '/audit', '/settings', '/api/pulse']) {
      expect(isPublicPath(p)).toBe(false);
    }
  });

  it('does not treat a lookalike as public', () => {
    expect(isPublicPath('/loginhack')).toBe(false);
    expect(isPublicPath('/api/authhack')).toBe(false);
  });
});
