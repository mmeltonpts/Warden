import type { PrismaClient } from '@prisma/client';

/**
 * How recently a scheduled job actually fed a queue.
 *
 * WHY THIS EXISTS
 *
 * The Reports and Alerts queues showed the same calm grey card whether you were caught up,
 * had picked an empty filter, or your ingest had been dead for six hours — and the card
 * told a tier 2 technician to SSH into a server and run a TypeScript command, which on a
 * normal fully-triaged day is both alarming and wrong.
 *
 * It matters more than it sounds. The near-miss this console was built after was 504
 * reports from 190 staff going to a decommissioned PhishER tenant: the detection worked,
 * and nothing was reading it. An empty queue during a live attack looking identical to a
 * quiet one is that same failure with a nicer font.
 *
 * `WardenKb4Account` already did this correctly — it renders a synced-at date and a
 * lastError, because its schema comment demanded it. The two queues that matter during an
 * attack were the ones that never got it.
 */
export interface Freshness {
  lastRunAt: Date | null;
  ok: boolean;
  detail: string | null;
  running: boolean;
  /** Minutes since the last run, or null if it has never run. */
  ageMinutes: number | null;
  /** The configured cadence, for the "overdue" judgement. */
  everyMinutes: number;
  /** Past twice its cadence, or failing, or never run. */
  stale: boolean;
}

export async function freshnessFor(
  prisma: PrismaClient,
  key: string,
  everyMinutes: number
): Promise<Freshness> {
  const row = await prisma.wardenScheduleState
    .findUnique({ where: { key } })
    .catch(() => null);

  const lastRunAt = row?.lastRunAt ?? null;
  const ageMinutes = lastRunAt ? Math.floor((Date.now() - lastRunAt.getTime()) / 60_000) : null;

  // Two cadences of grace before calling it overdue: one missed tick is a slow scan, two
  // is a pattern. A job with the interval set to 0 is disabled, not late.
  const overdue = everyMinutes > 0 && ageMinutes !== null && ageMinutes > everyMinutes * 2;

  return {
    lastRunAt,
    ok: row?.lastOk ?? true,
    detail: row?.lastDetail ?? null,
    running: row?.running ?? false,
    ageMinutes,
    everyMinutes,
    stale: everyMinutes > 0 && (lastRunAt === null || overdue || row?.lastOk === false)
  };
}

/** "14 minutes ago", "2 hours ago", "never". Short enough for a header line. */
export function ago(minutes: number | null): string {
  if (minutes === null) return 'never';
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const h = Math.floor(minutes / 60);
  if (h < 24) return `${h} hour${h === 1 ? '' : 's'} ago`;
  const d = Math.floor(h / 24);
  return `${d} day${d === 1 ? '' : 's'} ago`;
}
