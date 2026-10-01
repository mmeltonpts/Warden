import { ago, type Freshness } from '@/lib/freshness';

/**
 * A one-line statement of whether this queue is being fed, and a distinct empty state.
 *
 * The rule it enforces: a failure must never look like calm. "Nothing here" and "nothing
 * is arriving" are different facts and get different colours, different wording, and
 * different advice.
 */
export function IngestStatus({ f, what }: { f: Freshness; what: string }) {
  if (f.everyMinutes === 0) {
    return (
      <p className="text-xs text-text-muted">
        Scheduled {what} ingestion is <strong>disabled</strong> in Settings &rarr; Schedule.
        Nothing new will appear here on its own.
      </p>
    );
  }
  return (
    <p className={`text-xs ${f.stale ? 'text-warning' : 'text-text-muted'}`}>
      Last {what} ingest {ago(f.ageMinutes)}
      {f.lastRunAt && <> ({f.lastRunAt.toISOString().slice(11, 16)}Z)</>}, every{' '}
      {f.everyMinutes} min.
      {f.running && ' Running now.'}
      {!f.ok && (
        <>
          {' '}
          <strong>The last run FAILED:</strong> {f.detail ?? 'no detail recorded'}
        </>
      )}
      {f.ok && f.stale && <> &mdash; overdue.</>}
    </p>
  );
}

export function EmptyQueue({ f, what }: { f: Freshness; what: string }) {
  // Broken beats empty: if the pipe is not running, say that first, because it changes
  // what the emptiness means.
  if (f.stale) {
    return (
      <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
        <strong className="text-danger">
          This queue is not being fed &mdash; the emptiness below means nothing.
        </strong>
        <p className="mt-1 text-text-muted">
          {f.lastRunAt === null
            ? `The ${what} ingest has never run on this host.`
            : `The last ${what} ingest was ${ago(f.ageMinutes)} and the cadence is every ${f.everyMinutes} minutes.`}
          {!f.ok && f.detail && <> The error was: {f.detail}</>} Check Settings &rarr; Schedule
          and the <code className="mono">warden-loginscan</code> timer before concluding that
          nothing has been reported. The incident this console was built after was 504 reports
          arriving safely somewhere nobody was reading.
        </p>
      </div>
    );
  }

  return (
    <div className="card text-sm text-text-muted">
      <strong className="text-text-primary">Nothing in this view.</strong> The {what} ingest
      ran {ago(f.ageMinutes)} and is up to date, so this is a caught-up queue or a filter with
      no matches &mdash; not a fault.
    </div>
  );
}
