import { describe, it, expect, vi, beforeEach } from 'vitest';

const files = new Map<string, string>();
vi.mock('node:fs/promises', () => ({
  readFile: async (p: string) => {
    const v = [...files.entries()].find(([k]) => p.endsWith(k))?.[1];
    if (v === undefined) throw new Error('ENOENT');
    return v;
  }
}));

import { readProgress } from './progress';

// Verbatim shapes from warden-loginscan's journal on 2026-09-28.
const Q = '((from:teacher@partner-two.example OR "Download Transcript Record PDF") newer_than:30d in:anywhere)';
const LOG = [
  `Getting all Messages that match query (${Q}) for aaron.a@example.org (1/1364)`,
  `Getting all Messages that match query (${Q}) for abby.turner@example.org (2/1364)`,
  `Got 1 Message that matched query (${Q}) for abby.turner@example.org`,
  `Getting all Messages that match query (${Q}) for zoe.adams@example.org (412/1364)`,
  `Got 3 Messages that matched query (${Q}) for zoe.adams@example.org`,
  `Got 0 Messages that matched query (${Q}) for nobody@example.org`
].join('\n');

beforeEach(() => files.clear());

describe('readProgress', () => {
  it('reads the latest mailbox position', async () => {
    files.set('job1.log', LOG);
    const p = await readProgress('job1');
    expect(p).toMatchObject({ done: 412, total: 1364, current: 'zoe.adams@example.org' });
  });

  it('sums matches and counts only mailboxes that actually hit', async () => {
    files.set('job1.log', LOG);
    const p = await readProgress('job1');
    expect(p?.matched).toBe(4);
    expect(p?.mailboxesHit).toBe(2);
  });

  it('returns null before GAM has written a position — never an invented number', async () => {
    files.set('job2.log', 'Initializing...\n');
    expect(await readProgress('job2')).toBeNull();
  });

  it('returns null when there is no log yet', async () => {
    expect(await readProgress('missing')).toBeNull();
  });

  it('is not fooled by an address inside the echoed query', async () => {
    const tricky = `Getting all Messages that match query ("verify for evil@attacker.com (9/9)" in:anywhere) for real.user@example.org (5/1364)`;
    files.set('job3.log', tricky);
    const p = await readProgress('job3');
    expect(p).toMatchObject({ done: 5, total: 1364, current: 'real.user@example.org' });
  });
});
