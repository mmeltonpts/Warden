/**
 * What counts as "sound the alarm". Pure, so the rules are testable apart from the route.
 */

export interface PulseItem {
  id: string;
  source: 'alert' | 'falcon';
  title: string;
  href: string;
  at: string;
  open: boolean; // still untriaged — drives the repeat
}

/** "HIGH, medium" → Set{"HIGH","MEDIUM"}. Blank means nothing qualifies, never everything. */
export function severitySet(list: string | null | undefined): Set<string> {
  return new Set(
    String(list ?? '')
      .split(/[,\n]/)
      .map((x) => x.trim().toUpperCase())
      .filter(Boolean)
  );
}

export function qualifies(severity: string | null | undefined, wanted: Set<string>): boolean {
  return Boolean(severity) && wanted.has(String(severity).trim().toUpperCase());
}

/** Clamp operator input so a typo cannot hammer the server or deafen a room. */
export function soundLimits(s: { volume: number; pollSeconds: number; repeatSeconds: number }) {
  const n = (v: unknown, d: number) => (Number.isFinite(Number(v)) ? Number(v) : d);
  return {
    volume: Math.min(100, Math.max(0, n(s.volume, 70))),
    pollSeconds: Math.min(600, Math.max(10, n(s.pollSeconds, 30))),
    repeatSeconds: n(s.repeatSeconds, 0) <= 0 ? 0 : Math.min(3600, Math.max(30, n(s.repeatSeconds, 0)))
  };
}
