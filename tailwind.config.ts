import type { Config } from 'tailwindcss';

/**
 * Warden design system.
 *
 * Permanent dark mode, no light theme. Elevation through background lightness only;
 * no shadows. Same token names as Sentinel and CampusLink so components copy-paste
 * between the three codebases unedited — see src/core/themes.ts.
 *
 * Every colour resolves through a CSS variable holding space-separated RGB channels,
 * so `THEME=campuslink` recolours the app at runtime without a rebuild and
 * `bg-surface/50` opacity modifiers still work.
 *
 * The accent here is deliberately calm slate rather than a brand red. In this app the
 * loud colour is `danger`, reserved for an action about to touch every mailbox in the
 * district. If the accent shouted too, that distinction would be lost.
 */
const rgb = (v: string) => `rgb(var(${v}) / <alpha-value>)`;

const config: Config = {
  darkMode: 'class',
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          nav: rgb('--bg-nav'),
          base: rgb('--bg-base'),
          surface: rgb('--bg-surface'),
          elevated: rgb('--bg-elevated')
        },
        border: rgb('--border'),
        text: {
          primary: rgb('--text-primary'),
          muted: rgb('--text-muted')
        },
        accent: rgb('--accent'),
        'accent-hover': rgb('--accent-hover'),

        success: rgb('--success'),
        danger: rgb('--danger'),
        warning: rgb('--warning'),
        info: rgb('--info'),

        // CampusLink aliases so ported components keep rendering.
        surface: rgb('--bg-base'),
        'surface-elevated': rgb('--bg-surface'),
        'surface-muted': rgb('--bg-elevated'),
        primary: rgb('--accent'),
        'primary-foreground': '#ffffff',
        'text-muted': rgb('--text-muted')
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace']
      },
      borderRadius: { DEFAULT: '0.375rem' }
    }
  },
  plugins: []
};

export default config;
