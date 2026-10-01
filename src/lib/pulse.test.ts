import { describe, it, expect } from 'vitest';
import { severitySet, qualifies, soundLimits } from './pulse';

describe('alert sound rules', () => {
  it('matches severities case-insensitively from a comma list', () => {
    const w = severitySet('High, critical\nMEDIUM');
    expect(qualifies('HIGH', w)).toBe(true);
    expect(qualifies('Critical', w)).toBe(true);
    expect(qualifies(' medium ', w)).toBe(true);
    expect(qualifies('LOW', w)).toBe(false);
  });

  it('a blank list sounds for nothing, never for everything', () => {
    expect(severitySet('').size).toBe(0);
    expect(qualifies('HIGH', severitySet(' , '))).toBe(false);
  });

  it('an alert with no severity never sounds', () => {
    expect(qualifies(null, severitySet('HIGH'))).toBe(false);
  });

  it('clamps volume, polling and repeat so a typo cannot hammer the server or deafen a room', () => {
    expect(soundLimits({ volume: 400, pollSeconds: 1, repeatSeconds: 5 })).toEqual({ volume: 100, pollSeconds: 10, repeatSeconds: 30 });
    expect(soundLimits({ volume: -3, pollSeconds: 99999, repeatSeconds: 0 })).toEqual({ volume: 0, pollSeconds: 600, repeatSeconds: 0 });
    expect(soundLimits({ volume: NaN, pollSeconds: NaN, repeatSeconds: NaN })).toEqual({ volume: 70, pollSeconds: 30, repeatSeconds: 0 });
  });
});
