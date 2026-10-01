import { describe, it, expect } from 'vitest';
import { FIELDS, DEFAULTS } from './settings';
import { SECTIONS, dig, patchFromForm, missingRequired, fieldsIn } from './settings-form';

const form = (o: Record<string, string>) => {
  const f = new FormData();
  for (const [k, v] of Object.entries(o)) f.append(k, v);
  return f;
};

describe('every setting is reachable', () => {
  it('every field belongs to a section the Settings page and the wizard show', () => {
    for (const f of FIELDS) expect(SECTIONS).toContain(f.section);
  });

  it('every field has a default, so a fresh install renders every input', () => {
    for (const f of FIELDS) expect(dig(DEFAULTS as never, f.key), f.key).not.toBeUndefined();
  });

  it('list fields default to arrays', () => {
    for (const f of FIELDS.filter((x) => x.type === 'list')) {
      expect(Array.isArray(dig(DEFAULTS as never, f.key)), f.key).toBe(true);
    }
  });

  it('ships with no district in it', () => {
    // A public build must not carry anyone's domain, address or console URL.
    expect(DEFAULTS.domains.staff).toBe('');
    expect(DEFAULTS.domains.students).toBe('');
    expect(DEFAULTS.districtIpPrefix).toBe('');
    expect(DEFAULTS.consoleUrl).toBe('');
    expect(DEFAULTS.reports.addresses).toBe('');
  });
});

describe('patchFromForm', () => {
  it('splits list fields one entry per line and drops blanks', () => {
    const p = patchFromForm('Google Workspace', form({ protectedSubjects: '[Phish Alert]\r\n\nDO NOT OPEN \n' }));
    expect(p.protectedSubjects).toEqual(['[Phish Alert]', 'DO NOT OPEN']);
  });

  it('never blanks a required field', () => {
    const p = patchFromForm('Google Workspace', form({ 'domains.staff': '   ', 'domains.students': '' }));
    expect(p.domains).toEqual({ students: '' });
  });

  it('keeps a masked secret unchanged', () => {
    const p = patchFromForm('CrowdStrike', form({ 'crowdstrike.clientSecret': '••••••••abcd', 'crowdstrike.clientId': 'id1' }));
    expect(p.crowdstrike).toEqual({ clientId: 'id1', enabled: false, notify: false });
  });

  it('ignores a select value that is not one of its options', () => {
    expect(patchFromForm('General', form({ theme: 'nope' })).theme).toBeUndefined();
    expect(patchFromForm('General', form({ theme: 'campuslink' })).theme).toBe('campuslink');
  });

  it('skips a blank or non-numeric number instead of writing NaN or 0', () => {
    const p = patchFromForm('Hunt', form({ 'hunt.senderWindowDays': '' }));
    expect(p.hunt).toBeUndefined();
    expect(patchFromForm('Hunt', form({ 'hunt.senderWindowDays': 'x' })).hunt).toBeUndefined();
  });

  it('only touches the posted section', () => {
    const p = patchFromForm('General', form({ consoleUrl: 'https://w.example.org:8443', 'domains.staff': 'evil.example' }));
    expect(p).toEqual({ consoleUrl: 'https://w.example.org:8443' });
  });
});

describe('missingRequired', () => {
  it('names the blank required fields of a section', () => {
    expect(missingRequired('Google Workspace', DEFAULTS as never).map((f) => f.key)).toEqual(['domains.staff']);
    expect(missingRequired('Google Workspace', { ...DEFAULTS, domains: { staff: 'example.org', students: '' } } as never)).toEqual([]);
  });

  it('sections without required fields never block', () => {
    expect(fieldsIn('Schedule').length).toBeGreaterThan(0);
    expect(missingRequired('Schedule', DEFAULTS as never)).toEqual([]);
  });
});
