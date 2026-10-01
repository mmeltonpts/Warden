/**
 * Student VPN notice queue. Run from the scheduler tick.
 *
 *   sudo -u warden npx tsx scripts/queue-student-vpn.ts
 *
 * Finds student sign-ins through a VPN or privacy relay in the recent login events, looks up
 * each student's building from the directory, and adds a row to the review queue routed to
 * that building's administrator. It sends NOTHING to a student: an administrator reviews each
 * row in the console and decides whether to send the handbook notice or dismiss it (for
 * example, an iPhone's default Private Relay, which is indistinguishable from a VPN here).
 *
 * Depends on student sign-in scanning being on (Sign-in risk tab), which is what stores
 * student login events in the first place.
 */
import { spawnSync } from 'node:child_process';
import { PrismaClient } from '@prisma/client';
import { getSettings } from '../src/lib/settings';
import { errText } from '../src/lib/errors';
import { lookupIp, classifyOrg } from '../src/lib/rdap';
import { parseBuildingMap, buildingAdminFor, duringSchoolHours } from '../src/lib/verify';

const prisma = new PrismaClient();

/** Directory building + OU for a student, from GAM. One quick per-student read. */
function directoryInfo(gamPath: string, email: string): { ou: string | null; building: string | null } {
  const r = spawnSync(gamPath, ['info', 'user', email, 'fields', 'orgunitpath,organizations'], {
    encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024
  });
  const out = r.stdout ?? '';
  const ou = out.match(/Google Org Unit Path:\s*(.+)/)?.[1]?.trim() ?? null;
  const building = out.match(/location:\s*(.+)/i)?.[1]?.trim() ?? null;
  return { ou, building };
}

async function main(): Promise<string> {
  const s = await getSettings(prisma);
  const cfg = s.studentVpn;
  if (!cfg.enabled) return 'disabled';
  if (!s.scanStudentSignIns) return 'skipped — student sign-in scanning is off';

  const studentSuffix = `@${s.domains.students.toLowerCase()}`;
  const since = new Date(Date.now() - Math.max(1, s.scanLookbackHours) * 3600_000 - 3600_000);
  const map = parseBuildingMap(cfg.buildingAdmins);
  const anonPatterns = (s.alerts.anonymizerOrgs ?? '').split(',').filter(Boolean);
  const resiPatterns = (s.alerts.residentialOrgs ?? '').split(',').filter(Boolean);
  const schoolDays = cfg.schoolDays.split(',').map((x) => Number(x.trim())).filter((n) => Number.isFinite(n));

  // Recent student sign-ins, newest first, de-duplicated to one per student+network so a
  // whole class behind one relay does not flood the queue.
  const events = await prisma.wardenLoginEvent.findMany({
    where: { mailbox: { endsWith: studentSuffix }, ts: { gte: since }, ip: { not: null }, eventName: 'login_success' },
    orderBy: { ts: 'desc' },
    take: 5000,
    select: { mailbox: true, ts: true, ip: true, geo: true }
  });

  const netClass = new Map<string, { anon: boolean; org: string | null }>();
  const dirCache = new Map<string, { ou: string | null; building: string | null }>();
  let queued = 0;
  const forAdmin = new Map<string, number>();

  for (const e of events) {
    if (!e.ip) continue;

    // Classify the network (cached per address-family prefix via lookupIp + a local memo).
    let nc = netClass.get(e.ip);
    if (!nc) {
      const info = await lookupIp(prisma, e.ip, { timeoutMs: 8000 }).catch(() => null);
      const klass = info ? classifyOrg(info, resiPatterns, anonPatterns).klass : 'unknown';
      nc = { anon: klass === 'anonymizer', org: info?.org || info?.name || null };
      netClass.set(e.ip, nc);
    }
    if (!nc.anon) continue;

    // Already queued this sign-in?
    if (await prisma.wardenStudentVpnNotice.findUnique({ where: { student_signInTs: { student: e.mailbox, signInTs: e.ts } } })) continue;

    const school = duringSchoolHours(e.ts, { offsetMinutes: cfg.utcOffsetMinutes, days: schoolDays, window: cfg.schoolWindow });
    if (cfg.schoolHoursOnly && !school) continue;

    let dir = dirCache.get(e.mailbox);
    if (!dir) { dir = directoryInfo(s.gamPath, e.mailbox); dirCache.set(e.mailbox, dir); }
    const adminEmail = buildingAdminFor(dir.ou, map);

    await prisma.wardenStudentVpnNotice.create({
      data: {
        student: e.mailbox,
        signInTs: e.ts,
        ip: e.ip,
        geo: e.geo,
        netOrg: nc.org,
        ouPath: dir.ou,
        building: dir.building,
        schoolHours: school,
        adminEmail,
        state: 'QUEUED'
      }
    });
    queued++;
    if (adminEmail) forAdmin.set(adminEmail, (forAdmin.get(adminEmail) ?? 0) + 1);
  }

  const routed = [...forAdmin.entries()].map(([a, n]) => `${a}:${n}`).join(', ');
  return `queued ${queued}${routed ? ` (${routed})` : ''}`;
}

if (require.main === module) {
  main().then((r) => console.log(r)).catch((e) => { console.error(errText(e)); process.exitCode = 1; }).finally(() => prisma.$disconnect());
}

export { main as runQueueStudentVpn };
