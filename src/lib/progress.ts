import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { LOG_DIR } from './gam';

/**
 * Live progress for a running GAM job, read from its stderr log.
 *
 * GAM prints one line per mailbox as it walks a domain:
 *
 *   Getting all Messages that match query (...) for jane.doe@example.org (412/1364)
 *   Got 2 Messages that matched query (...) for jane.doe@example.org
 *
 * and `run()` in gam.ts already streams stderr to `<LOG_DIR>/<jobId>.log` while the job
 * runs. The job page used to show a spinner and an elapsed clock for 8–15 minutes while
 * this file sat there with the exact answer in it.
 *
 * Everything here is parsed from real output. If GAM changes its wording the parse
 * returns null and the page falls back to the elapsed clock — it never invents a number.
 */
export interface Progress {
  done: number;
  total: number;
  /** Mailbox GAM is on right now. */
  current: string | null;
  /** Messages matched so far, summed from "Got N Message(s)" lines. */
  matched: number;
  /** Mailboxes with at least one match so far. */
  mailboxesHit: number;
}

// Anchored to end of line: the query itself is echoed inside each line, and a lure string
// containing " for someone@example.org" must not be mistaken for the mailbox GAM is on.
const POSITION = /for (\S+@\S+) \((\d+)\/(\d+)\)\s*$/gm;
const GOT = /^Got (\d+) Messages? that match(?:ed)? query.* for (\S+@\S+)\s*$/gm;

export async function readProgress(jobId: string): Promise<Progress | null> {
  let text: string;
  try {
    text = await readFile(path.join(LOG_DIR, `${jobId}.log`), 'utf8');
  } catch {
    return null; // not started writing yet
  }

  let last: RegExpExecArray | null = null;
  for (const m of text.matchAll(POSITION)) last = m as RegExpExecArray;
  if (!last) return null;

  let matched = 0;
  const hit = new Set<string>();
  for (const m of text.matchAll(GOT)) {
    const n = Number(m[1]);
    if (n > 0) {
      matched += n;
      // Real GAM lines end "…for jane@example.org..." — strip the trailing ellipsis.
      hit.add(m[2].replace(/\.+$/, '').toLowerCase());
    }
  }

  return {
    done: Number(last[2]),
    total: Number(last[3]),
    current: last[1],
    matched,
    mailboxesHit: hit.size
  };
}
