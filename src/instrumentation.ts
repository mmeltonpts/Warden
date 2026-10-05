/**
 * Next runs this once per server process. Starting the worker here (rather than in a
 * route handler) means it runs whether or not anyone has loaded a page — a queued
 * sweep must not wait for a browser.
 *
 * startWorker() is idempotent and pins to globalThis; see src/lib/worker.ts.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { startWorker } = await import('./lib/worker');
    startWorker();

    // Pin the display zone once for this server process so every page renders timestamps in
    // the district's local time. Read from Settings; a change takes effect on the next
    // restart. Best-effort — a settings read failing must never stop the worker from starting.
    try {
      const { prisma } = await import('./lib/db');
      const { getSettings } = await import('./lib/settings');
      const { setDefaultTz } = await import('./lib/time');
      const s = await getSettings(prisma);
      setDefaultTz(s.timezone);
    } catch {
      /* fall back to host zone */
    }
  }
}
