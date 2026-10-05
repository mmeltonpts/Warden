'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

/**
 * Keeps the Jobs LIST current while the queue is draining.
 *
 * The detail page already updates itself (src/app/jobs/[id]/Live.tsx), but the list sat
 * still: you queued a sweep, watched the row say QUEUED, and had to hand-refresh to see it
 * go RUNNING then DONE. This polls on the same 5s cadence as Live — but only while at least
 * one job is still QUEUED or RUNNING, and only when the tab is actually visible, so a list
 * of finished jobs makes no requests at all.
 *
 * router.refresh() re-runs the server component and swaps in fresh rows in place: no
 * navigation, no scroll jump. When the last active job reaches a terminal status the next
 * refresh renders with active=false and the polling stops on its own.
 */
export function AutoRefresh({ active }: { active: boolean }) {
  const router = useRouter();

  useEffect(() => {
    if (!active) return;
    const poll = setInterval(() => {
      // A hidden tab doesn't need live rows; skip the refresh and resume when it's shown.
      if (typeof document !== 'undefined' && document.hidden) return;
      router.refresh();
    }, 5000);
    return () => clearInterval(poll);
  }, [active, router]);

  return null;
}
