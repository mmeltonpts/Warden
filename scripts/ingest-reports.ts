/**
 * Ingest staff phish reports into the triage queue.
 *
 *   sudo -u warden npx tsx scripts/ingest-reports.ts
 *
 * Reads the mailboxes the Phish Alert Button forwards to, pulls the ORIGINAL sender,
 * subject and payload hosts out of each forwarded copy, and files a WardenReport.
 *
 * Reports matching the KNOWN_GOOD list are filed as KNOWN_GOOD rather than dropped —
 * the reporter still gets credit, and the suppression is visible and reversible.
 *
 * Read-only against Google. Safe to re-run: reports de-duplicate on Gmail message id.
 */
import { PrismaClient } from '@prisma/client';
import { spawn } from 'node:child_process';
import { getSettings } from '../src/lib/settings';
import { parseReportBody, isKnownGood, campaignKey, reportQuery, dedupeKey } from '../src/lib/reports';
import { gamCompleted } from '../src/lib/gam';

const prisma = new PrismaClient();

/** Bodies are normally a few KB. Cap defensively so one pathological message cannot
 *  bloat the row; truncation is visible on the detail page. */
const BODY_CAP = 64_000;

/**
 * stderr MUST be drained or inherited — never left as an unread pipe.
 *
 * GAM writes one progress line per mailbox to stderr. Across 1,363 mailboxes that overflows
 * the 64KB pipe buffer, and GAM then blocks forever on the write while this process sits
 * waiting for stdout that will never come. Observed 2026-09-23: 21 minutes wall-clock,
 * 8 seconds of CPU, state S. It looks exactly like a slow scan and is in fact a deadlock.
 *
 * Both streams are piped and drained into buffers, which avoids that deadlock AND lets the
 * caller see the exit code and stderr. The exit code is the whole point: a scan that GAM
 * aborted returns the same "0 rows" as a genuinely empty mailbox, and the report ingest used
 * to call both "no reports found". stderr is echoed to this process so the scan progress still
 * shows in the scheduler log.
 */
function gam(
  gamPath: string,
  args: string[],
  timeoutMs = 1_800_000
): Promise<{ out: string; stderr: string; code: number; timedOut: boolean }> {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let timedOut = false;
    const c = spawn(gamPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const t = setTimeout(() => { timedOut = true; c.kill('SIGKILL'); }, timeoutMs);
    c.stdout.on('data', (d) => (out += d));
    c.stderr.on('data', (d) => { err += d; process.stderr.write(d); });
    c.on('error', () => resolve({ out, stderr: err, code: -1, timedOut }));
    c.on('close', (code) => {
      clearTimeout(t);
      resolve({ out, stderr: err, code: code ?? -1, timedOut });
    });
  });
}

function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * `--days N` overrides the configured lookback for a one-time backfill. The setting
 * stays at 7 for the scheduled run; a 180-day sweep is a migration, not a cadence.
 */
function argDays(): number | null {
  const i = process.argv.indexOf('--days');
  if (i < 0) return null;
  const n = Number(process.argv[i + 1]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

export async function run(opts: { days?: number } = {}) {
  void opts;
  const s = await getSettings(prisma);
  const addresses = s.reports.addresses.split(',').map((a) => a.trim()).filter(Boolean);
  if (!addresses.length) {
    console.log('no report mailboxes configured');
    return { created: 0, backfilled: 0, suppressed: 0, skipped: 0, createdIds: [] as string[] };
  }
  const days = argDays() ?? s.reports.lookbackDays;

  const knownGood = (
    await prisma.wardenIoc.findMany({ where: { kind: 'KNOWN_GOOD' }, select: { value: true } })
  ).map((k) => k.value);

  const query = reportQuery(addresses, days);
  console.log(`scanning ${s.domains.staff} (${days}d lookback) for: ${query}`);

  const scan = await gam(s.gamPath, [
    'domains_ns', s.domains.staff, 'print', 'messages',
    'query', query, 'headers', 'From,To,Subject,Date'
  ]);

  // A scan that did not finish is NOT "no reports". GAM aborting (a disabled mailbox, a quota
  // error, a timeout) returns the same zero rows as a genuinely quiet week, and the ingest used
  // to print "no reports found" either way — the founding incident of this codebase, rebuilt in
  // the one job whose silence means "nobody is being protected". Fail loudly instead, so the
  // scheduler records lastOk=false and it shows as a failed ingest rather than an all-clear.
  if (!gamCompleted(scan.code, scan.timedOut, scan.stderr)) {
    throw new Error(
      `report scan did not complete — GAM ${scan.timedOut ? 'timed out' : `exited ${scan.code}`}` +
        `: ${scan.stderr.trim().split('\n').slice(-2).join(' ').slice(0, 300)}. ` +
        'This is NOT "no reports" — the scan could not be read.'
    );
  }

  const lines = scan.out.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) {
    console.log('no reports found');
    return { created: 0, backfilled: 0, suppressed: 0, skipped: 0, createdIds: [] as string[] };
  }
  const header = splitCsv(lines[0]);
  const col = (n: string) => header.indexOf(n);

  let created = 0;
  let suppressed = 0;
  let skipped = 0;
  let backfilled = 0;
  const createdIds: string[] = [];
  const campaigns = new Map<string, number>();

  for (let i = 1; i < lines.length; i++) {
    const c = splitCsv(lines[i]);
    const mailbox = c[col('User')];
    const msgId = c[col('id')];
    if (!mailbox || !msgId) continue;

    // A row without a body is not "already seen" — it was ingested before bodies were
    // stored, and an analyst cannot triage a subject line. Re-fetch those in place.
    const existing = await prisma.wardenReport.findUnique({ where: { msgId } });
    if (existing?.bodyText) {
      skipped++;
      continue;
    }

    // The expensive call. Only for reports we have no body for. Best-effort per message: a
    // single body that will not fetch leaves that report without a body (re-fetched next run),
    // which is a world apart from the whole scan silently returning nothing.
    const body = (await gam(s.gamPath, [
      'user', mailbox, 'show', 'messages', 'ids', msgId, 'showbody'
    ], 120_000)).out;

    const parsed = parseReportBody(body, mailbox, [s.domains.staff, s.domains.students].filter(Boolean));
    const kg = isKnownGood(parsed, knownGood);
    const reportedTo = (c[col('To')] ?? '').toLowerCase();

    let reportedAt = new Date();
    const raw = c[col('Date')];
    if (raw) {
      const d = new Date(raw);
      if (!Number.isNaN(d.getTime())) reportedAt = d;
    }

    const extracted = {
      originalSender: parsed.originalSender ?? null,
      originalSubject: parsed.originalSubject ?? null,
      originalTo: parsed.originalTo ?? null,
      payloadHosts: JSON.stringify(parsed.payloadHosts),
      payloadUrls: JSON.stringify(parsed.payloadUrls ?? []),
      bodyText: body.slice(0, BODY_CAP),
      dedupeKey: dedupeKey(mailbox, parsed.originalSender, parsed.originalSubject)
    };

    // Upsert, not findUnique-then-create. The same Gmail message id can appear twice in one
    // scan — ids are unique within a mailbox, not across the domain — and the read-then-write
    // version died with P2002 part-way through a 504-report backfill, losing the whole run.
    //
    // The update branch carries ONLY the extracted fields: state, notes and reviewedBy stay
    // untouched, so re-running an ingest can never undo somebody's triage.
    const wasNew = !existing;
    const saved = await prisma.wardenReport.upsert({
      where: { msgId },
      create: {
        msgId,
        reporter: mailbox,
        reportedAt,
        reportedTo,
        ...extracted,
        state: kg.suppressed ? 'KNOWN_GOOD' : 'NEW',
        notes: kg.suppressed ? `Suppressed: matched known-good "${kg.matched}"` : null
      },
      update: extracted
    });
    if (wasNew) createdIds.push(saved.id);
    if (existing) backfilled++;
    else if (kg.suppressed) suppressed++;
    else created++;

    if (!kg.suppressed) {
      const k = campaignKey(parsed);
      campaigns.set(k, (campaigns.get(k) ?? 0) + 1);
    }
  }

  console.log(`\n${created} new, ${backfilled} backfilled with bodies, ${suppressed} suppressed as known-good, ${skipped} already complete`);
  if (campaigns.size) {
    console.log('\ngrouped into campaigns:');
    for (const [k, n] of [...campaigns.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15)) {
      console.log(`  ${String(n).padStart(4)}  ${k}`);
    }
  }

  return { created, backfilled, suppressed, skipped, createdIds };
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('ingest-reports')) {
  run()
    .then((r) => { if (r && typeof r !== 'string') console.log(JSON.stringify(r)); })
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}