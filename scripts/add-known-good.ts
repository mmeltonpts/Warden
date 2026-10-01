/**
 * Record confirmed-legitimate mail that staff repeatedly report.
 *
 *   sudo -u warden npx tsx scripts/add-known-good.ts <file.json>
 *   sudo -u warden npx tsx scripts/add-known-good.ts --list
 *
 * Why this table exists: a district's own background-check vendor, or its HR system, sends
 * recurring notices that name the district and imply urgency — so staff report them, every
 * time. Without a known-good list each recurrence costs triage time and teaches people that
 * reporting achieves nothing.
 *
 * A KNOWN_GOOD entry suppresses incident creation. It does NOT hide the report: the
 * reporter still gets credit, the entry carries the reason it was suppressed, and it is
 * visible and removable. Matching is a case-insensitive substring test against the
 * original sender and subject — see isKnownGood() in src/lib/reports.ts.
 *
 * The entries are a FILE, not a constant, because they name your vendors and the staff who
 * reported them. Keep yours in `private/`, which is gitignored.
 *
 * FILE FORMAT:
 *   [ { "value": "no-reply@vendor.example", "notes": "Why this is legitimate, and who confirmed it." } ]
 */
import { PrismaClient } from '@prisma/client';
import { readFileSync } from 'node:fs';

const prisma = new PrismaClient();

async function main() {
  const arg = process.argv[2];

  if (arg === '--list') {
    const rows = await prisma.wardenIoc.findMany({
      where: { kind: 'KNOWN_GOOD' },
      orderBy: { addedAt: 'desc' }
    });
    if (!rows.length) {
      console.log('no known-good entries');
      return;
    }
    for (const r of rows) {
      console.log(`  ${r.value}`);
      if (r.notes) console.log(`      ${r.notes}`);
    }
    return;
  }

  if (!arg) {
    console.error('usage: npx tsx scripts/add-known-good.ts <file.json>');
    console.error('       npx tsx scripts/add-known-good.ts --list');
    console.error('       see the comment at the top of this file for the format');
    process.exitCode = 1;
    return;
  }

  let entries: Array<{ value: string; notes?: string }>;
  try {
    entries = JSON.parse(readFileSync(arg, 'utf8'));
  } catch (e) {
    console.error(`could not read ${arg}: ${(e as Error).message}`);
    process.exitCode = 1;
    return;
  }

  let added = 0;
  let present = 0;
  for (const k of entries) {
    if (!k?.value) continue;
    const existing = await prisma.wardenIoc.findUnique({ where: { value: k.value } });
    if (existing) {
      present++;
      continue;
    }
    await prisma.wardenIoc.create({
      data: {
        kind: 'KNOWN_GOOD',
        value: k.value,
        notes: k.notes ?? null,
        addedBy: 'add-known-good'
      }
    });
    console.log(`+ ${k.value}`);
    added++;
  }
  console.log(`\n${added} added, ${present} already present`);
}

main()
  .catch((e) => { console.error(e); process.exitCode = 1; })
  .finally(() => prisma.$disconnect());
