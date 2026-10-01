/**
 * One-time backfill of sign-in history.
 *
 *   sudo -u warden npx tsx scripts/backfill-logins.ts --since 2026-06-01
 *   sudo -u warden npx tsx scripts/backfill-logins.ts --since 2026-06-01 --score
 *
 * WHY THIS EXISTS
 *
 * The scheduled scan only ever looks back `scanLookbackHours`, so Warden's history began
 * the day it was installed. With five days of data the average baseline held 15 events and
 * only 27% were mature — and an immature baseline over-flags, because a network seen once
 * cannot be told apart from a network seen for the first time by an intruder.
 *
 * Google keeps this history regardless. Pulling it turns "we started watching on Tuesday"
 * into "we know what normal looks like for this person", which is the entire premise of
 * scoring against a learned baseline rather than a fixed rule.
 *
 * FLAGS ARE NOT RAISED BY DEFAULT, and that is deliberate. Re-scoring four months of
 * history would produce hundreds of alerts about sign-ins that were investigated weeks ago
 * or never mattered, and the first thing anyone does with a queue like that is stop reading
 * it. `--score` runs the assessment and PRINTS what it would have flagged without writing
 * anything — useful as a test of whether the scoring actually separates the known
 * compromises from the noise.
 *
 * Read-only against Google.
 */
import { PrismaClient } from '@prisma/client';
import { fetchLoginEvents } from '../src/lib/loginscan';
import { buildBaseline, assessRisk, ipPrefix, type RawLoginEvent } from '../src/lib/baseline';
import { getSettings } from '../src/lib/settings';

const prisma = new PrismaClient();

function arg(name: string): string | null {
  const i = process.argv.indexOf(name);
  return i >= 0 ? (process.argv[i + 1] ?? null) : null;
}

export async function run() {
  const settings = await getSettings(prisma);
  const sinceRaw = arg('--since') ?? '2026-06-01';
  const since = new Date(sinceRaw + (sinceRaw.length === 10 ? 'T00:00:00Z' : ''));
  if (Number.isNaN(since.getTime())) {
    console.error(`bad --since value: ${sinceRaw}`);
    process.exitCode = 1;
    return;
  }
  const score = process.argv.includes('--score');

  const before = await prisma.wardenLoginEvent.count();
  // Same domain choice as the scheduled scan, so the history built here matches the
  // population that gets scored. --students forces it on for a one-off backfill without
  // changing the setting.
  const scanDomains = [settings.domains.staff];
  if ((settings.scanStudentSignIns || process.argv.includes('--students')) && settings.domains.students) {
    scanDomains.push(settings.domains.students);
  }
  console.log(`fetching sign-in events for ${scanDomains.join(', ')} since ${since.toISOString()}`);
  console.log('(this is one paginated API call, not a per-mailbox scan — but four months is a lot of pages)\n');

  const events = await fetchLoginEvents(settings.gamPath, since, scanDomains);
  console.log(`fetched ${events.length.toLocaleString()} events`);
  if (!events.length) {
    console.log('nothing returned — check GAM auth and the --since date');
    return;
  }

  // Insert in chunks. A single createMany of several hundred thousand rows will exhaust
  // the parameter limit long before it exhausts memory.
  const CHUNK = 2000;
  let inserted = 0;
  for (let i = 0; i < events.length; i += CHUNK) {
    const slice = events.slice(i, i + CHUNK);
    const res = await prisma.wardenLoginEvent.createMany({
      data: slice.map((e) => ({
        mailbox: e.mailbox,
        ts: e.ts,
        eventName: e.eventName,
        ip: e.ip ?? null,
        ipPrefix: ipPrefix(e.ip) ?? null,
        asn: e.asn ?? null,
        geo: e.geo ?? null,
        challenge: e.challenge ?? null,
        suspicious: !!e.suspicious,
        sensitive: e.sensitive ?? null
      })),
      skipDuplicates: true
    });
    inserted += res.count;
    if (i % 20000 === 0 && i) console.log(`  ...${i.toLocaleString()} processed, ${inserted.toLocaleString()} new`);
  }
  const after = await prisma.wardenLoginEvent.count();
  console.log(`\n${inserted.toLocaleString()} new events stored (${before.toLocaleString()} -> ${after.toLocaleString()})`);

  // ── rebuild every baseline from the widened window ──────────────────────────
  const windowStart = new Date(Date.now() - settings.baselineWindowDays * 86_400_000);
  const mailboxes = (
    await prisma.wardenLoginEvent.findMany({
      where: { ts: { gte: windowStart } },
      select: { mailbox: true },
      distinct: ['mailbox']
    })
  ).map((m) => m.mailbox);

  console.log(`\nrebuilding baselines for ${mailboxes.length.toLocaleString()} mailboxes ` +
    `(${settings.baselineWindowDays}-day window)`);

  let rebuilt = 0;
  let mature = 0;
  const wouldFlag: Array<{ mailbox: string; ts: Date; score: number; reasons: string[]; ip: string | null }> = [];

  for (const mailbox of mailboxes) {
    const rows = await prisma.wardenLoginEvent.findMany({
      where: { mailbox, ts: { gte: windowStart } },
      orderBy: { ts: 'asc' }
    });
    const history: RawLoginEvent[] = rows.map((r) => ({
      mailbox: r.mailbox, ts: r.ts, eventName: r.eventName, ip: r.ip,
      asn: r.asn, geo: r.geo, challenge: r.challenge,
      suspicious: r.suspicious, sensitive: r.sensitive
    }));

    const b = buildBaseline(mailbox, history);
    const firstSeen = history.length ? history[0].ts : null;
    const lastSeen = history.length ? history[history.length - 1].ts : null;
    await prisma.wardenBaseline.upsert({
      where: { mailbox },
      create: {
        mailbox,
        knownPrefixes: JSON.stringify(b.knownPrefixes),
        knownAsns: JSON.stringify(b.knownAsns),
        knownGeos: JSON.stringify(b.knownGeos),
        knownChallenges: JSON.stringify(b.knownChallenges),
        usesPasskey: b.usesPasskey,
        typicalHours: JSON.stringify(b.typicalHours),
        eventCount: b.eventCount,
        firstSeen,
        lastSeen,
        mature: b.mature
      },
      update: {
        knownPrefixes: JSON.stringify(b.knownPrefixes),
        knownAsns: JSON.stringify(b.knownAsns),
        knownGeos: JSON.stringify(b.knownGeos),
        knownChallenges: JSON.stringify(b.knownChallenges),
        usesPasskey: b.usesPasskey,
        typicalHours: JSON.stringify(b.typicalHours),
        eventCount: b.eventCount,
        firstSeen,
        lastSeen,
        mature: b.mature,
        rebuiltAt: new Date()
      }
    });
    rebuilt++;
    if (b.mature) mature++;

    // Optional assessment. Nothing is written — this only reports what the engine would
    // have said, so the scoring can be judged against incidents whose outcome is known.
    if (score) {
      for (const e of history) {
        const r = assessRisk(e, b);
        if (r.flag) wouldFlag.push({ mailbox, ts: e.ts, score: r.score, reasons: r.reasons, ip: e.ip ?? null });
      }
    }
  }

  console.log(`\n${rebuilt.toLocaleString()} baselines rebuilt, ${mature.toLocaleString()} mature ` +
    `(${rebuilt ? Math.round((mature / rebuilt) * 100) : 0}%)`);

  if (score) {
    wouldFlag.sort((a, b2) => b2.score - a.score);
    console.log(`\n--score: the engine WOULD have flagged ${wouldFlag.length} sign-ins (nothing written)\n`);
    for (const f of wouldFlag.slice(0, 30)) {
      console.log(
        String(f.score).padStart(4) + '  ' +
        f.ts.toISOString().slice(0, 16).replace('T', ' ') + '  ' +
        f.mailbox.padEnd(40) + (f.ip ?? '').padEnd(40) + f.reasons.slice(0, 2).join(' · ')
      );
    }
    if (wouldFlag.length > 30) console.log(`  ... and ${wouldFlag.length - 30} more`);
  }
}

if (process.argv[1]?.includes('backfill-logins')) {
  run()
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}
