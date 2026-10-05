import { describe, it, expect } from 'vitest';
import { collapseByNetwork, type ScoredFlag } from './loginscan';

const f = (p: Partial<ScoredFlag>): ScoredFlag => ({
  ts: new Date('2026-10-05T00:19:00Z'), score: 50, reasons: ['New network for this user'],
  ip: '198.51.100.140', asn: 'AS36180', geo: 'US-TX', challenge: null, suspicious: false, ...p
});

describe('collapseByNetwork', () => {
  it('collapses repeated sign-ins from the same network into one flag', () => {
    // A staff phone: four sign-ins, same /24, same minute, identical risk signature.
    const out = collapseByNetwork([
      f({ ts: new Date('2026-10-05T00:18:30Z') }),
      f({ ts: new Date('2026-10-05T00:19:01Z') }),
      f({ ts: new Date('2026-10-05T00:19:20Z') }),
      f({ ts: new Date('2026-10-05T00:19:40Z') })
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].reasons.join(' ')).toMatch(/4 sign-ins from this network/);
  });

  it('keeps the worst-scoring event in a collapsed group', () => {
    const out = collapseByNetwork([
      f({ score: 50, reasons: ['New network for this user'] }),
      f({ score: 85, suspicious: true, reasons: ['Google flagged this sign-in as suspicious', 'New network for this user'] })
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].score).toBe(85);
    expect(out[0].suspicious).toBe(true);
    expect(out[0].reasons.join(' ')).toMatch(/suspicious/);
  });

  it('never merges different networks', () => {
    const out = collapseByNetwork([
      f({ ip: '198.51.100.140', geo: 'US-TX' }),
      f({ ip: '203.0.113.9', geo: 'US-CA', score: 60 })
    ]);
    expect(out).toHaveLength(2);
    expect(out[0].score).toBe(60); // sorted worst-first
  });

  it('collapses an IPv6 burst on the /48', () => {
    const out = collapseByNetwork([
      f({ ip: '2001:db8:abcd:1:2:3:4:5' }),
      f({ ip: '2001:db8:abcd:9:8:7:6:5' })
    ]);
    expect(out).toHaveLength(1);
  });

  it('passes a single flag through unchanged', () => {
    const out = collapseByNetwork([f({})]);
    expect(out).toHaveLength(1);
    expect(out[0].reasons).toEqual(['New network for this user']);
  });
});
