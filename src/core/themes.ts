/**
 * Theme presets.
 *
 * Token names, geometry and dark-mode discipline are identical to Sentinel and
 * CampusLink, so components copy-paste between all three codebases unedited.
 * The theme is a setting (Settings → General) and recolours the app without a rebuild.
 *
 * Severity colours (success/danger/warning/info) are deliberately NOT part of the
 * brand channel — same rule as Sentinel. In Warden the reason is operational rather
 * than life-safety: `danger` marks a destructive action about to touch every mailbox
 * in the district, and a district must not be able to restyle that into something
 * that reads as routine.
 */
export type ThemeName = 'warden' | 'campuslink';

export interface ThemeTokens {
  '--bg-nav': string;
  '--bg-base': string;
  '--bg-surface': string;
  '--bg-elevated': string;
  '--border': string;
  '--text-primary': string;
  '--text-muted': string;
  '--accent': string;
  '--accent-hover': string;
  '--success': string;
  '--danger': string;
  '--warning': string;
  '--info': string;
}

/** Shared across every preset. Changing these is a policy decision, not theming. */
const SEVERITY = {
  '--success': '39 174 96', //  #27ae60
  '--danger': '192 57 43', //   #c0392b
  '--warning': '240 169 59', // #f0a93b
  '--info': '41 128 185' //     #2980b9
} as const;

export const THEMES: Record<ThemeName, { label: string; tokens: ThemeTokens }> = {
  /** Default. Neutral — no CampusLink or district marks. */
  warden: {
    label: 'Warden (neutral)',
    tokens: {
      '--bg-nav': '18 21 26', //          #12151a
      '--bg-base': '23 27 33', //         #171b21
      '--bg-surface': '30 35 43', //      #1e232b
      '--bg-elevated': '39 45 55', //     #272d37
      '--border': '51 59 71', //          #333b47
      '--text-primary': '230 233 239', // #e6e9ef
      '--text-muted': '139 147 161', //   #8b93a1
      '--accent': '90 122 155', //        #5a7a9b slate — deliberately calm; the
      '--accent-hover': '116 152 189', // #7498bd loud colour here is `danger`
      ...SEVERITY
    }
  },

  /** CampusLink "Ember Admin". Tokens lifted verbatim from CampusLink's tailwind.config.ts. */
  campuslink: {
    label: 'CampusLink (Ember Admin)',
    tokens: {
      '--bg-nav': '20 20 20', //          #141414
      '--bg-base': '28 28 28', //         #1c1c1c
      '--bg-surface': '36 36 36', //      #242424
      '--bg-elevated': '46 46 46', //     #2e2e2e
      '--border': '58 58 58', //          #3a3a3a
      '--text-primary': '232 234 240', // #e8eaf0
      '--text-muted': '138 138 138', //   #8a8a8a
      // NOT CampusLink's ember #c0392b, and this is not a styling preference.
      //
      // #c0392b is byte-identical to `--danger`. With it here, `.btn-primary` and
      // `.btn-danger` render the same, and `.btn:hover` tints EVERY button in the app with
      // the destructive colour. "Save settings" then looks exactly like "Trash 412
      // messages across 7,697 mailboxes", which is the one distinction this console cannot
      // afford to lose at 22:00.
      //
      // The header of this file says a district must not be able to restyle `danger` into
      // something routine. This is the same failure approached from the other side:
      // restyling the routine into something that reads as danger destroys the signal just
      // as completely. Any brand colour is fine here EXCEPT red — see themes.test.ts,
      // which fails the build if an accent ever collides with a severity colour again.
      '--accent': '95 125 149', //        #5f7d95 steel
      '--accent-hover': '123 156 182', // #7b9cb6 — clears WCAG 1.4.11 3:1 on focus rings
      ...SEVERITY
    }
  }
};

export const DEFAULT_THEME: ThemeName = 'warden';

export function resolveTheme(name: string | undefined): ThemeName {
  return name === 'campuslink' || name === 'warden' ? name : DEFAULT_THEME;
}

/** Inline <style> payload for the root layout. */
export function themeStyle(name: ThemeName): string {
  const tokens = THEMES[name].tokens;
  const body = Object.entries(tokens)
    .map(([k, v]) => `${k}: ${v};`)
    .join(' ');
  return `:root { ${body} }`;
}
