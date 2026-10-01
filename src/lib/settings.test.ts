import { describe, it, expect } from 'vitest';

/**
 * Regression: saving one KnowBe4 token wiped the other.
 *
 * The Settings form patches with dotted paths, so changing one nested field produces an
 * object containing ONLY that field. A shallow spread then replaced the whole parent.
 */
function deepMerge<T extends Record<string, unknown>>(base: T, patch: Record<string, unknown>): T {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) continue;
    const cur = out[k];
    if (v && typeof v === 'object' && !Array.isArray(v) &&
        cur && typeof cur === 'object' && !Array.isArray(cur)) {
      out[k] = deepMerge(cur as Record<string, unknown>, v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out as T;
}

describe('settings deep merge', () => {
  const base = {
    gamPath: '/opt/gam7/gam',
    domains: { staff: 'example.org', students: 'student.example.org' },
    knowbe4: {
      enabled: true,
      reportingToken: 'REPORTING-SECRET',
      userEventsToken: 'EVENTS-SECRET',
      timeoutSeconds: 20
    },
    protectedSubjects: ['[Phish Alert]', 'DO NOT OPEN']
  };

  it('keeps the sibling token when only one is saved', () => {
    const out = deepMerge(base, { knowbe4: { reportingToken: 'NEW-REPORTING' } });
    expect(out.knowbe4.reportingToken).toBe('NEW-REPORTING');
    expect(out.knowbe4.userEventsToken).toBe('EVENTS-SECRET'); // the bug
    expect(out.knowbe4.enabled).toBe(true);
    expect(out.knowbe4.timeoutSeconds).toBe(20);
  });

  it('keeps the other domain when one is changed', () => {
    const out = deepMerge(base, { domains: { staff: 'new.example.org' } });
    expect(out.domains.staff).toBe('new.example.org');
    expect(out.domains.students).toBe('student.example.org');
  });

  it('replaces arrays wholesale rather than merging element-wise', () => {
    const out = deepMerge(base, { protectedSubjects: ['Only This'] });
    expect(out.protectedSubjects).toEqual(['Only This']);
  });

  it('leaves untouched top-level values alone', () => {
    const out = deepMerge(base, { knowbe4: { enabled: false } });
    expect(out.gamPath).toBe('/opt/gam7/gam');
    expect(out.knowbe4.reportingToken).toBe('REPORTING-SECRET');
  });
});

/**
 * Regression: the READ path lost nested defaults.
 *
 * `getSettings` used `{ ...DEFAULTS, ...stored }`. The stored `knowbe4` object replaced the
 * entire default block, so `knowbe4.eventTypes` — which has no form field and therefore is
 * never part of a patch — came back `undefined`. `kb4Health` then threw on `Object.values()`.
 *
 * It was self-perpetuating, which is why it survived several saves: the lossy read fed
 * `saveSettings`, which deep-merged the patch onto the already-lossy object and wrote it
 * back still missing the key.
 */
describe('settings read path fills nested defaults', () => {
  const DEFAULTS = {
    gamPath: '/opt/gam7/gam',
    knowbe4: {
      enabled: false,
      reportingToken: '',
      userEventsToken: '',
      eventTypes: {
        compromise: 'Warden: Account Takeover Confirmed',
        realPhishClick: 'Warden: Clicked Real Phishing Link'
      },
      timeoutSeconds: 20
    },
    ai: { enabled: false, command: ['claude', '-p', '{prompt}'], timeoutSeconds: 120 }
  };

  // Exactly the shape of the production row on 2026-09-23: no eventTypes, no ai.command.
  const stored = {
    gamPath: '/opt/gam7/gam',
    knowbe4: { enabled: true, reportingToken: 'SAVED-REPORTING', userEventsToken: 'SAVED-EVENTS' },
    ai: { enabled: false, timeoutSeconds: 120 }
  };

  it('restores nested defaults the stored row never carried', () => {
    const out = deepMerge(DEFAULTS, stored);
    expect(out.knowbe4.eventTypes).toBeDefined();
    expect(Object.values(out.knowbe4.eventTypes)).toHaveLength(2);
    expect(out.ai.command).toEqual(['claude', '-p', '{prompt}']);
  });

  it('still lets stored values win over defaults', () => {
    const out = deepMerge(DEFAULTS, stored);
    expect(out.knowbe4.enabled).toBe(true);
    expect(out.knowbe4.reportingToken).toBe('SAVED-REPORTING');
    expect(out.knowbe4.timeoutSeconds).toBe(20);
  });

  it('a shallow spread drops them — this is the bug being guarded', () => {
    const shallow = { ...DEFAULTS, ...stored };
    expect((shallow.knowbe4 as Record<string, unknown>).eventTypes).toBeUndefined();
    expect((shallow.ai as Record<string, unknown>).command).toBeUndefined();
  });
});

import { SENSITIVE_KEYS } from './crypto';
import { FIELDS as ALL_FIELDS } from './settings';
import { falconBase } from './crowdstrike';

describe('every field marked sensitive is actually encrypted', () => {
  // Encryption matches by leaf key NAME. feeds.abuseChAuthKey was marked sensitive, told
  // the operator "Encrypted at rest", and was stored in plaintext because its name was
  // never added to SENSITIVE_KEYS. This fails the build the next time that happens.
  it.each(ALL_FIELDS.filter((f) => 'sensitive' in f && f.sensitive).map((f) => [f.key as string]))(
    '%s',
    (key) => {
      expect(SENSITIVE_KEYS.has(key.split('.').pop()!), `${key} is marked sensitive but its leaf name is not in SENSITIVE_KEYS`).toBe(true);
    }
  );
});

describe('falconBase', () => {
  it('maps each cloud to its API host', () => {
    expect(falconBase('us-1')).toBe('https://api.crowdstrike.com');
    expect(falconBase('US-2')).toBe('https://api.us-2.crowdstrike.com');
  });
  it('refuses an unknown cloud rather than guessing', () => {
    expect(falconBase('us-3')).toBeNull();
    expect(falconBase('')).toBeNull();
  });
});

describe('falconBase accepts the URL Falcon shows', () => {
  it('maps the GovCloud base URL', () => {
    expect(falconBase('https://api.laggar.gcw.crowdstrike.com')).toBe('https://api.laggar.gcw.crowdstrike.com');
    expect(falconBase('api.laggar.gcw.crowdstrike.com/')).toBe('https://api.laggar.gcw.crowdstrike.com');
    expect(falconBase('us-gov-1')).toBe('https://api.laggar.gcw.crowdstrike.com');
  });
  it('refuses any host that is not CrowdStrike — the secret must not leave for elsewhere', () => {
    expect(falconBase('https://evil.example.com')).toBeNull();
    expect(falconBase('https://api.crowdstrike.com.evil.example')).toBeNull();
  });
});
