import { describe, it, expect, afterEach } from 'vitest';
import { fmtTs, fmtDate, fmtClock, setDefaultTz } from './time';

// A fixed instant: 2026-10-04 22:40 UTC. In October the US is still on daylight time
// (DST ends 2026-11-01), so Chicago is CDT (UTC-5) and New York is EDT (UTC-4).
const INSTANT = new Date('2026-10-04T22:40:00Z');

describe('time formatting', () => {
  afterEach(() => setDefaultTz(undefined)); // never leak a default into the next test

  it('renders date + time + zone in an explicit zone', () => {
    expect(fmtTs(INSTANT, 'America/Chicago')).toBe('2026-10-04 17:40 CDT');
    expect(fmtTs(INSTANT, 'America/New_York')).toBe('2026-10-04 18:40 EDT');
  });

  it('renders date-only and time-only variants', () => {
    expect(fmtDate(INSTANT, 'America/Chicago')).toBe('2026-10-04');
    expect(fmtClock(INSTANT, 'America/Chicago')).toBe('17:40 CDT');
  });

  it('crosses the date boundary when the zone pushes it to the previous day', () => {
    // 00:30 UTC is still the evening before in Chicago — the exact bug that motivated this.
    const lateUtc = new Date('2026-10-05T00:30:00Z');
    expect(fmtTs(lateUtc, 'America/Chicago')).toBe('2026-10-04 19:30 CDT');
  });

  it('uses the process default when no zone is passed', () => {
    setDefaultTz('America/New_York');
    expect(fmtTs(INSTANT)).toBe('2026-10-04 18:40 EDT');
    // An explicit argument still overrides the default.
    expect(fmtTs(INSTANT, 'America/Chicago')).toBe('2026-10-04 17:40 CDT');
  });

  it('treats a blank default as "use the host zone" without throwing', () => {
    setDefaultTz('   ');
    expect(fmtTs(INSTANT)).not.toBe(''); // renders in whatever the host zone is
  });

  it('degrades a bad zone to the host zone instead of throwing', () => {
    expect(() => fmtTs(INSTANT, 'Not/ARealZone')).not.toThrow();
    expect(fmtTs(INSTANT, 'Not/ARealZone')).not.toBe('');
  });

  it('returns empty string for null, undefined and invalid input', () => {
    expect(fmtTs(null)).toBe('');
    expect(fmtTs(undefined)).toBe('');
    expect(fmtTs('not a date')).toBe('');
    expect(fmtDate(null)).toBe('');
    expect(fmtClock(null)).toBe('');
  });

  it('accepts ISO strings and epoch millis, not just Date objects', () => {
    expect(fmtTs('2026-10-04T22:40:00Z', 'America/Chicago')).toBe('2026-10-04 17:40 CDT');
    expect(fmtTs(INSTANT.getTime(), 'America/Chicago')).toBe('2026-10-04 17:40 CDT');
  });
});
