import { describe, it, expect } from 'vitest';
import { THEMES, resolveTheme, DEFAULT_THEME } from './themes';

/**
 * These are safety assertions wearing the clothes of style tests.
 *
 * `danger` in this console marks an action that trashes mail across up to 7,697 mailboxes.
 * It only works as a warning while it is reserved. The CampusLink preset shipped with
 * `--accent: 192 57 43`, byte-identical to `--danger`, which made `.btn-primary` and
 * `.btn-danger` render the same and tinted every hover in the app with the destructive
 * colour. Nobody noticed, because it is invisible unless you diff two token values.
 */
const SEVERITY_TOKENS = ['--danger', '--warning', '--success', '--info'] as const;
const BRAND_TOKENS = ['--accent', '--accent-hover'] as const;

describe('theme presets', () => {
  const names = Object.keys(THEMES) as Array<keyof typeof THEMES>;

  it.each(names)('%s: no brand colour collides with a severity colour', (name) => {
    const t = THEMES[name].tokens;
    for (const brand of BRAND_TOKENS) {
      for (const sev of SEVERITY_TOKENS) {
        expect(
          t[brand],
          `${name}.${brand} is the same colour as ${sev}. A district may pick any brand ` +
            `colour except one that reads as a severity — see the comment in themes.ts.`
        ).not.toBe(t[sev]);
      }
    }
  });

  it.each(names)('%s: severity colours are identical across every preset', (name) => {
    // Severity is policy, not theming. A district must not be able to restyle the colour
    // that marks district-wide mail deletion.
    const base = THEMES[DEFAULT_THEME].tokens;
    for (const sev of SEVERITY_TOKENS) {
      expect(THEMES[name].tokens[sev]).toBe(base[sev]);
    }
  });

  it.each(names)('%s: defines every token, none blank', (name) => {
    for (const [k, v] of Object.entries(THEMES[name].tokens)) {
      expect(v, `${name}.${k} is empty`).toMatch(/^\d{1,3} \d{1,3} \d{1,3}$/);
    }
  });

  it('falls back to the neutral theme for unknown or missing names', () => {
    expect(resolveTheme(undefined)).toBe(DEFAULT_THEME);
    expect(resolveTheme('')).toBe(DEFAULT_THEME);
    expect(resolveTheme('nope')).toBe(DEFAULT_THEME);
    expect(resolveTheme('campuslink')).toBe('campuslink');
  });
});
