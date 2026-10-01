'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

/**
 * The first client component in this codebase, and it exists for one reason.
 *
 * A QUEUED or RUNNING job used to render a header and empty space. Every panel on the job
 * page requires a terminal status, so during the 8–15 minutes a scope takes across 1,363
 * mailboxes the operator saw nothing at all: no progress, no elapsed time, no indication
 * the thing was alive. The most consequential screen in the product was a blank page you
 * had to remember to hand-refresh.
 *
 * A ticking clock and a periodic `router.refresh()`. On each refresh the server re-reads
 * GAM's stderr log (src/lib/progress.ts), which carries a "(412/1364)" position per
 * mailbox, so the bar is GAM's own count — not an animation. If that parse finds nothing
 * (GAM not writing yet, or its wording changed) this falls back to the elapsed clock
 * rather than inventing a percentage.
 */
export function Live({
  startedAt,
  status,
  expectedSeconds,
  queuedAhead,
  progress
}: {
  startedAt: string | null;
  status: string;
  expectedSeconds: number;
  queuedAhead: number;
  progress: { done: number; total: number; current: string | null; matched: number; mailboxesHit: number } | null;
}) {
  const router = useRouter();
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    // Five seconds is frequent enough to feel live and slow enough that a full page
    // re-render of a job page costs nothing worth measuring.
    const poll = setInterval(() => router.refresh(), 5000);
    return () => {
      clearInterval(tick);
      clearInterval(poll);
    };
  }, [router]);

  const elapsed = startedAt ? Math.max(0, Math.floor((now - Date.parse(startedAt)) / 1000)) : 0;
  const mm = Math.floor(elapsed / 60);
  const ss = String(elapsed % 60).padStart(2, '0');
  const over = expectedSeconds > 0 && elapsed > expectedSeconds;

  if (status === 'QUEUED') {
    return (
      <div className="card text-sm">
        <strong>Waiting to start.</strong>{' '}
        <span className="text-text-muted">
          {queuedAhead > 0
            ? `${queuedAhead} job${queuedAhead === 1 ? '' : 's'} ahead of this one — the worker runs one at a time, so a long scan in front of this will hold it.`
            : 'Next in line. The worker picks up queued jobs every few seconds.'}{' '}
          This page updates itself.
        </span>
      </div>
    );
  }

  // Real progress from GAM's own per-mailbox output, when it has any. ETA is the observed
  // rate so far, extrapolated — honest about being an estimate, and only shown once enough
  // mailboxes have gone by for the rate to mean something.
  if (progress && progress.total > 0) {
    const pct = Math.min(100, Math.round((progress.done / progress.total) * 100));
    const rate = elapsed > 0 ? progress.done / elapsed : 0;
    const remaining = rate > 0 ? Math.round((progress.total - progress.done) / rate) : null;
    const eta =
      remaining !== null && progress.done >= 20
        ? `~${Math.floor(remaining / 60)}m ${String(remaining % 60).padStart(2, '0')}s left`
        : 'estimating…';
    return (
      <div className="card space-y-2 text-sm">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <strong>
            Mailbox {progress.done.toLocaleString()} of {progress.total.toLocaleString()} ({pct}%)
          </strong>
          <span className="text-xs text-text-muted">
            {mm}m {ss}s elapsed · {eta}
          </span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded bg-bg-elevated">
          <div className="h-full rounded" style={{ width: `${pct}%`, background: 'rgb(var(--accent))' }} />
        </div>
        <div className="text-xs text-text-muted">
          <strong className="text-text-primary">{progress.matched.toLocaleString()}</strong> matching
          message{progress.matched === 1 ? '' : 's'} so far in{' '}
          <strong className="text-text-primary">{progress.mailboxesHit.toLocaleString()}</strong>{' '}
          mailbox{progress.mailboxesHit === 1 ? '' : 'es'}
          {progress.current && <> · now on <span className="mono">{progress.current}</span></>}
          . Running totals are a floor until it finishes. This page updates itself.
        </div>
      </div>
    );
  }

  return (
    <div className="card text-sm">
      <strong>
        Running — {mm}m {ss}s
      </strong>{' '}
      <span className="text-text-muted">
        {over
          ? 'This is longer than usual for this job. GAM walks every mailbox in the domain, ' +
            'and a large domain or a slow response can stretch it. It will be marked ' +
            'INCOMPLETE rather than DONE if it hits the scan timeout.'
          : 'GAM walks every mailbox in the domain. This page updates itself; you can leave it.'}
      </span>
    </div>
  );
}
