/**
 * Remove indicator hits that a hunt should never have recorded.
 *
 *   sudo -u warden npx tsx scripts/purge-hunt-hits.ts --surface mailbox --before 2026-09-28T17:00
 *   sudo -u warden npx tsx scripts/purge-hunt-hits.ts --surface mailbox --before ... --commit
 *
 * WHY THIS EXISTS
 *
 * On 28 September 2026 the scheduled hunt ran with two defects and wrote 1,863 rows:
 *
 *   - Sender indicators carried no date window, so three compromised partner-district
 *     accounts matched their own legitimate mail across the full lookback. 526 rows came
 *     from three partner-district staff sending cross-country schedules and weather
 *     protocols.
 *   - Attribution fell back to the first lure string in the list when nothing matched, so
 *     1,255 unrelated messages were labelled "Download Transcript Record PDF", an indicator
 *     from a different campaign.
 *
 * Both are fixed in src/lib/hunt.ts. The rows they produced are still in the database, and
 * they are worse than useless: `record()` de-duplicates against existing rows, so a bad row
 * suppresses the good finding that would replace it.
 *
 * ONLY `surface = 'mailbox'` IS AFFECTED. The report and login surfaces are matched locally
 * against payload hosts and sign-in events, never through a Gmail query, so neither defect
 * could touch them. The payload-host hits and attacker-IP sign-ins are
 * real findings and must survive — hence --surface rather than a table truncate.
 *
 * DRY BY DEFAULT. Nothing is deleted without --commit.
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

function arg(name: string): string | null {
  const i = process.argv.indexOf(name);
  return i >= 0 ? (process.argv[i + 1] ?? null) : null;
}

export async function run() {
  const commit = process.argv.includes('--commit');
  const surface = arg('--surface');
  const beforeRaw = arg('--before');
  const iocValue = arg('--ioc');

  if (!surface && !beforeRaw && !iocValue) {
    console.error('refusing to run with no filter — pass at least one of --surface, --before, --ioc');
    process.exitCode = 1;
    return;
  }

  const where: Record<string, unknown> = {};
  if (surface) where.surface = surface;
  if (iocValue) where.iocValue = iocValue;
  if (beforeRaw) {
    const before = new Date(beforeRaw.length === 10 ? `${beforeRaw}T00:00:00Z` : beforeRaw);
    if (Number.isNaN(before.getTime())) {
      console.error(`bad --before value: ${beforeRaw}`);
      process.exitCode = 1;
      return;
    }
    where.ts = { lt: before };
  }

  const total = await prisma.wardenIocHit.count();
  const matched = await prisma.wardenIocHit.count({ where });
  console.log(`${matched} of ${total} hits match ${JSON.stringify(where)}\n`);

  if (!matched) {
    console.log('nothing to do');
    return 'nothing to do';
  }

  // Show what is being removed, grouped, so the decision is made on evidence rather than
  // on a number. Anything unexpected in this list means the filter is wrong.
  const groups = await prisma.wardenIocHit.groupBy({
    by: ['iocValue', 'kind', 'surface'],
    where,
    _count: { _all: true }
  });
  for (const g of groups.sort((a, b) => b._count._all - a._count._all).slice(0, 20)) {
    console.log(`  ${String(g._count._all).padStart(6)}  ${g.kind.padEnd(13)} ${g.surface.padEnd(8)} ${g.iocValue.slice(0, 55)}`);
  }
  if (groups.length > 20) console.log(`  ... and ${groups.length - 20} more indicators`);

  // State what SURVIVES. A purge described only by what it removes invites the mistake of
  // deleting a surface nobody was thinking about.
  const surviving = await prisma.wardenIocHit.groupBy({
    by: ['surface'],
    where: { NOT: where as never },
    _count: { _all: true }
  });
  console.log('\nsurviving:');
  for (const s of surviving) console.log(`  ${String(s._count._all).padStart(6)}  ${s.surface}`);

  if (!commit) {
    console.log(`\n--commit not given: nothing deleted. ${matched} rows would be removed.`);
    return `${matched} would be removed`;
  }

  const res = await prisma.wardenIocHit.deleteMany({ where });
  console.log(`\n${res.count} rows deleted, ${await prisma.wardenIocHit.count()} remain`);
  return `${res.count} deleted`;
}

if (process.argv[1]?.includes('purge-hunt-hits')) {
  run()
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}
