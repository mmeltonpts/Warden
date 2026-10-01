import { describe, it, expect } from 'vitest';
import { huntTerms, attribute, UNATTRIBUTED, type HuntableIoc } from './hunt';

const ADDED = new Date('2026-09-20T00:00:00Z');

function ioc(p: Partial<HuntableIoc> & { value: string; kind: string }): HuntableIoc {
  return { addedAt: ADDED, ...p };
}

describe('huntTerms', () => {
  it('scopes a sender to a window around firstSeen', () => {
    const t = huntTerms(
      [ioc({ value: 'mmcbride@partner-district.example', kind: 'SENDER', firstSeen: new Date('2026-09-08T00:00:00Z') })],
      5
    );
    expect(t).toEqual(['(from:mmcbride@partner-district.example after:2026/09/03 before:2026/09/13)']);
  });

  it('never emits a bare from:, even when firstSeen is null', () => {
    // The regression that mattered. A partner-district account is compromised for days and
    // is the real person either side of that; unscoped, it matches their whole career.
    const t = huntTerms([ioc({ value: 'mmcbride@partner-district.example', kind: 'SENDER', firstSeen: null })], 5);
    expect(t[0]).toContain('after:');
    expect(t[0]).toContain('before:');
    expect(t[0]).not.toBe('from:mmcbride@partner-district.example');
  });

  it('falls back to addedAt when firstSeen is null', () => {
    const t = huntTerms([ioc({ value: 'x@y.org', kind: 'SENDER', firstSeen: null })], 2);
    expect(t).toEqual(['(from:x@y.org after:2026/09/18 before:2026/09/22)']);
  });

  it('leaves lure strings unwindowed and quoted', () => {
    // Lure text is not tied to one account's compromise window, so it is not date-scoped.
    const t = huntTerms([ioc({ value: 'Download Transcript Record PDF', kind: 'LURE_STRING' })], 5);
    expect(t).toEqual(['"Download Transcript Record PDF"']);
  });

  it('strips embedded quotes so one indicator cannot break the whole query', () => {
    const t = huntTerms([ioc({ value: 'say "hello"', kind: 'LURE_STRING' })], 5);
    expect(t).toEqual(['"say hello"']);
  });

  it('respects a widened window from settings', () => {
    const t = huntTerms([ioc({ value: 'a@b.org', kind: 'SENDER', firstSeen: new Date('2026-09-10T00:00:00Z') })], 1);
    expect(t).toEqual(['(from:a@b.org after:2026/09/09 before:2026/09/11)']);
  });
});

describe('attribute', () => {
  const iocs = [
    ioc({ value: 'mmcbride@partner-district.example', kind: 'SENDER' }),
    ioc({ value: 'Download Transcript Record PDF', kind: 'LURE_STRING' })
  ];

  it('credits the sender when the From matches', () => {
    const hit = attribute('Mia McBride <mmcbride@partner-district.example>', 'Cross Country', iocs);
    expect(hit?.value).toBe('mmcbride@partner-district.example');
  });

  it('credits a lure only when it is actually in the subject', () => {
    const hit = attribute('someone@example.org', 'Download Transcript Record PDF - action needed', iocs);
    expect(hit?.kind).toBe('LURE_STRING');
  });

  it('returns null rather than blaming an unrelated lure', () => {
    // The bug: this returned 'Download Transcript Record PDF' for every [Internal] Estate
    // Sales message, an indicator from a completely different campaign.
    expect(attribute('finance@example.org', '[Internal] Estate Sales', iocs)).toBeNull();
  });

  it('is case-insensitive on both sides', () => {
    expect(attribute('MMCBRIDE@PARTNER-DISTRICT.EXAMPLE', null, iocs)?.kind).toBe('SENDER');
    expect(attribute('x@y.org', 'download transcript record pdf', iocs)?.kind).toBe('LURE_STRING');
  });

  it('prefers the sender when both could match', () => {
    const hit = attribute('mmcbride@partner-district.example', 'Download Transcript Record PDF', iocs);
    expect(hit?.kind).toBe('SENDER');
  });

  it('exposes a marker distinct from any real indicator value', () => {
    expect(UNATTRIBUTED).toMatch(/not determined/);
    expect(iocs.some((i) => i.value === UNATTRIBUTED)).toBe(false);
  });
});

import { huntExclusions, isOwnTraffic } from './hunt';

describe('hunt excludes Warden’s own traffic', () => {
  const own = { wardenFrom: 'Warden <warden@example.org>', protectedSubjects: ['[Phish Alert]', 'DO NOT OPEN'] };

  it('excludes Warden’s sending address and responder subjects in the query', () => {
    const x = huntExclusions(own);
    expect(x).toContain('-from:warden@example.org');
    expect(x).toContain('-subject:"[Phish Alert]"');
  });

  it('does NOT exclude the whole staff domain — an internal account sending the lure is a finding', () => {
    expect(huntExclusions(own)).not.toMatch(/-from:example\.org(\s|$)/);
    expect(isOwnTraffic({ from: 'compromised.teacher@example.org', subject: 'Inv 80044710620' }, own)).toBe(false);
  });

  it.each([
    // The three false hits from 2026-09-29, verbatim.
    ['warden@example.org', '[Internal] Warden: 1 new phish report — [External Sender] Inv 80044710620'],
    ['pat.morgan@example.org', '[Phish Alert]  [External Sender] Inv 80044710620']
  ])('drops own traffic: %s', (from, subject) => {
    expect(isOwnTraffic({ from, subject }, own)).toBe(true);
  });

  it('keeps the actual attack', () => {
    expect(isOwnTraffic({ from: 'attacker@bec-sender.example', subject: '[External Sender] Inv 80044710620' }, own)).toBe(false);
  });

  it('drops Warden notifications by subject even when the from setting is blank', () => {
    expect(isOwnTraffic({ from: 'x@example.org', subject: '[Internal] Warden: 3 indicator matches' }, { protectedSubjects: [] })).toBe(true);
  });
});
