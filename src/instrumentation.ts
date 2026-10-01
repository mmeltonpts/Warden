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
  }
}
