/**
 * Mirror the KnowBe4 KSAT roster into Postgres.
 *
 *   sudo -u warden npx tsx scripts/sync-knowbe4.ts
 *
 * Why a mirror rather than live calls: the roster is ~2,600 users, which is six paginated
 * requests and roughly twenty seconds — far too slow for a page load. And the entire value
 * of this data is JOINING it against Warden's own tables (risk flags, reports, baselines),
 * which SQL can only do if both sides live in the same database.
 *
 * KSAT is the system of record. This table is a cache and is safe to drop and rebuild.
 *
 * Read-only against KnowBe4. Nothing here pushes events.
 */
import { PrismaClient } from '@prisma/client';
import { getSettings } from '../src/lib/settings';
import { fetchAccount, fetchUsers, fetchSecurityTests } from '../src/lib/knowbe4';

const prisma = new PrismaClient();

function asDate(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export async function run(opts: { days?: number } = {}) {
  void opts;
  const s = await getSettings(prisma);
  if (!s.knowbe4.enabled) {
    console.log('KnowBe4 is disabled in Settings — nothing to sync.');
    return '';
  }

  // ── account ────────────────────────────────────────────────────────────────
  const acct = await fetchAccount(s.knowbe4);
  if (acct.status !== 'ok' || !acct.data) {
    const err = `${acct.status}${acct.httpStatus ? ` (HTTP ${acct.httpStatus})` : ''}${acct.error ? `: ${acct.error}` : ''}`;
    console.error(`account fetch failed: ${err}`);
    await prisma.wardenKb4Account.upsert({
      where: { id: 1 },
      create: { id: 1, name: 'unknown', lastError: err },
      update: { lastError: err, syncedAt: new Date() }
    });
    process.exitCode = 1;
    return '';
  }
  const a = acct.data;
  console.log(`account: ${a.name} — ${a.subscription_level ?? '?'}, ${a.number_of_seats ?? '?'} seats, risk ${a.current_risk_score ?? '?'}`);

  // ── users ──────────────────────────────────────────────────────────────────
  const users = await fetchUsers(s.knowbe4);
  // 'ok' means the roster is COMPLETE. Anything else may still carry a partial roster,
  // which is worth writing — but it must not be allowed to drive removals.
  const complete = users.status === 'ok';
  const rows = (users.data ?? []).filter((u) => u.email);

  if (!rows.length) {
    const err = `${users.status}${users.httpStatus ? ` (HTTP ${users.httpStatus})` : ''}${users.error ? `: ${users.error}` : ''}`;
    console.error(`user fetch failed: ${err}`);
    await prisma.wardenKb4Account.update({ where: { id: 1 }, data: { lastError: err } }).catch(() => undefined);
    process.exitCode = 1;
    return '';
  }
  if (!complete) {
    console.warn(
      `WARNING: roster fetch returned "${users.status}" with ${rows.length} users.\n` +
        '         Refreshing those rows, but SKIPPING removal of anyone absent — a partial\n' +
        '         roster must never be able to delete people who are still in KSAT.'
    );
  }
  console.log(`fetched ${rows.length} users${complete ? '' : ' (INCOMPLETE)'}`);

  const now = new Date();
  let written = 0;
  for (const u of rows) {
    const data = {
      email: u.email.toLowerCase(),
      firstName: u.first_name ?? null,
      lastName: u.last_name ?? null,
      jobTitle: u.job_title ?? null,
      department: u.department ?? null,
      division: u.division ?? null,
      location: u.location ?? null,
      managerEmail: u.manager_email ? u.manager_email.toLowerCase() : null,
      employeeNumber: u.employee_number ?? null,
      phishPronePct: typeof u.phish_prone_percentage === 'number' ? u.phish_prone_percentage : null,
      riskScore: typeof u.current_risk_score === 'number' ? u.current_risk_score : null,
      status: u.status ?? null,
      groupIds: JSON.stringify(u.groups ?? []),
      aliases: JSON.stringify(u.aliases ?? []),
      provisioningManaged: Boolean(u.provisioning_managed),
      joinedOn: asDate(u.joined_on),
      lastSignIn: asDate(u.last_sign_in),
      syncedAt: now
    };
    await prisma.wardenKb4User.upsert({
      where: { kb4Id: u.id },
      create: { kb4Id: u.id, ...data },
      update: data
    });
    written++;
  }

  // Anything not refreshed this run no longer exists in KSAT — but only if this run saw the
  // WHOLE roster. Two guards, because they catch different accidents: `complete` catches
  // truncated pagination on our side, and the 10% ceiling catches a KSAT-side mishap (a
  // failed directory import, a bad bulk edit) that would otherwise propagate here as a
  // mass deletion the moment we mirrored it.
  let removed = { count: 0 };
  if (!complete) {
    console.log('removal pass SKIPPED — roster was incomplete');
  } else {
    const stale = await prisma.wardenKb4User.count({ where: { syncedAt: { lt: now } } });
    if (stale > rows.length * 0.1) {
      const msg = `refused to remove ${stale} users (>10% of a ${rows.length}-user roster) — investigate KSAT before re-running`;
      console.error(`REFUSED: ${msg}`);
      await prisma.wardenKb4Account.update({ where: { id: 1 }, data: { lastError: msg } }).catch(() => undefined);
    } else {
      removed = await prisma.wardenKb4User.deleteMany({ where: { syncedAt: { lt: now } } });
    }
  }

  await prisma.wardenKb4Account.upsert({
    where: { id: 1 },
    create: {
      id: 1,
      name: a.name,
      subscriptionLevel: a.subscription_level ?? null,
      subscriptionEnds: asDate(a.subscription_end_date),
      seats: a.number_of_seats ?? null,
      riskScore: a.current_risk_score ?? null,
      admins: JSON.stringify(
        (a.admins ?? []).map((x) => ({
          name: [x.first_name, x.last_name].filter(Boolean).join(' ') || x.email,
          email: x.email
        }))
      ),
      userCount: written,
      syncedAt: now,
      lastError: null
    },
    update: {
      name: a.name,
      subscriptionLevel: a.subscription_level ?? null,
      subscriptionEnds: asDate(a.subscription_end_date),
      seats: a.number_of_seats ?? null,
      riskScore: a.current_risk_score ?? null,
      admins: JSON.stringify(
        (a.admins ?? []).map((x) => ({
          name: [x.first_name, x.last_name].filter(Boolean).join(' ') || x.email,
          email: x.email
        }))
      ),
      userCount: written,
      syncedAt: now,
      lastError: null
    }
  });

  console.log(`\n${written} users written, ${removed.count} stale rows removed`);

  // ── what the data says, stated plainly ─────────────────────────────────────
  const active = await prisma.wardenKb4User.count({ where: { status: 'active' } });
  const neverSignedIn = await prisma.wardenKb4User.count({ where: { lastSignIn: null } });
  const highPpp = await prisma.wardenKb4User.count({ where: { phishPronePct: { gte: 40 } } });

  console.log(`  active status      : ${active}`);
  console.log(`  never signed in    : ${neverSignedIn}`);
  console.log(`  phish-prone >= 40% : ${highPpp}`);
  if (a.number_of_seats && written > a.number_of_seats) {
    console.log(
      `\n  NOTE: ${written} users against ${a.number_of_seats} seats. The roster is larger than\n` +
        `  the licence, which usually means archived or departed staff are still present.`
    );
  }

  const tests = await fetchSecurityTests(s.knowbe4);
  if (tests.status === 'ok') {
    const list = tests.data ?? [];
    const recent = list.filter((t) => {
      const d = asDate(t.started_at);
      return d && Date.now() - d.getTime() < 365 * 86_400_000;
    });
    console.log(`\n  phishing simulations: ${list.length} total, ${recent.length} in the last year`);
    if (!recent.length) {
      console.log('  No simulation has run in the last year. Phish-prone percentages are therefore');
      console.log('  historical, and for most users reflect nothing that has been measured recently.');
    }
  }
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('sync-knowbe4')) {
  run()
    .then((r) => { if (r && typeof r !== 'string') console.log(JSON.stringify(r)); })
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}