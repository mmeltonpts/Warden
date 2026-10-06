/**
 * One place that turns a stored UTC timestamp into something an operator reads.
 *
 * Everything in the database is UTC (Google's logs, GAM, our own rows). People kept having to
 * do the "subtract five hours" math in their head, and a flag that says 22:40Z reads as
 * late-night when it was actually 5:40pm in the building. So every user-facing timestamp goes
 * through here and is rendered in the district's local time, with the zone shown so it is never
 * ambiguous.
 *
 * `tz` is the IANA zone from Settings (e.g. "America/Chicago"). Blank/unknown falls back to the
 * host's own zone, which on a district VM is already local time. A bad zone string must never
 * throw in the middle of rendering a page, so it degrades to the host zone.
 */
/**
 * Process-wide default zone, set once at startup from the `timezone` setting (see
 * instrumentation.ts and the scheduler), so the 30-odd render sites can call fmtTs(date)
 * without every one of them loading settings and threading a tz argument.
 *
 * Pinned on `globalThis`, NOT a module-level `let`: in the built app, `instrumentation.ts`
 * and the page/route modules do not reliably share a module instance (the same cross-instance
 * hazard CLAUDE.md flags for the job worker). A plain `let` set in instrumentation's copy was
 * invisible to the render sites' copy, so every timestamp silently fell back to the host zone
 * (UTC) no matter what the setting said. globalThis is the one binding both instances share.
 * A settings change takes effect on the next restart, which is fine for something that
 * changes ~never.
 */
const TZ_KEY = '__wardenDefaultTz';
type TzHolder = { [TZ_KEY]?: string };
export function setDefaultTz(tz: string | undefined | null): void {
  (globalThis as TzHolder)[TZ_KEY] = tz ? String(tz).trim() || undefined : undefined;
}
function defaultTz(): string | undefined {
  return (globalThis as TzHolder)[TZ_KEY];
}

type Mode = 'date' | 'datetime' | 'time';

function parts(d: Date, tz: string | undefined, mode: Mode): string {
  const wantDate = mode !== 'time';
  const wantTime = mode !== 'date';
  const opts: Intl.DateTimeFormatOptions = {
    ...(wantDate ? { year: 'numeric', month: '2-digit', day: '2-digit' } : {}),
    ...(wantTime ? { hour: '2-digit', minute: '2-digit', hour12: false, timeZoneName: 'short' } : {})
  };
  const zone = tz || defaultTz() || undefined;
  let fmt: Intl.DateTimeFormat;
  try {
    fmt = new Intl.DateTimeFormat('en-CA', { ...opts, timeZone: zone });
  } catch {
    fmt = new Intl.DateTimeFormat('en-CA', opts); // bad tz -> host zone
  }
  const p = Object.fromEntries(fmt.formatToParts(d).map((x) => [x.type, x.value]));
  const date = wantDate ? `${p.year}-${p.month}-${p.day}` : '';
  if (!wantTime) return date;
  const time = `${p.hour}:${p.minute}${p.timeZoneName ? ' ' + p.timeZoneName : ''}`;
  return date ? `${date} ${time}` : time;
}

function toDate(d: Date | string | number | null | undefined): Date | null {
  if (d === null || d === undefined) return null;
  const dt = d instanceof Date ? d : new Date(d);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

/** "2026-10-04 17:40 CDT" in the district's zone. Empty string for null/invalid. */
export function fmtTs(d: Date | string | number | null | undefined, tz?: string): string {
  const dt = toDate(d);
  return dt ? parts(dt, tz, 'datetime') : '';
}

/** "2026-10-04" in the district's zone. */
export function fmtDate(d: Date | string | number | null | undefined, tz?: string): string {
  const dt = toDate(d);
  return dt ? parts(dt, tz, 'date') : '';
}

/** "17:40 CDT" in the district's zone — for compact inline spots where the date is implied. */
export function fmtClock(d: Date | string | number | null | undefined, tz?: string): string {
  const dt = toDate(d);
  return dt ? parts(dt, tz, 'time') : '';
}
