/**
 * The scheduler.
 *
 *   sudo -u warden npx tsx scripts/tick.ts
 *
 * ONE systemd timer calls this every couple of minutes. It reads the configured interval
 * for each job from Settings and runs only what is actually due.
 *
 * WHY NOT FOUR TIMERS: a timer is a root-owned file in /etc/systemd/system. "How often do
 * we check for new phishing reports" is an operational decision an admin should be able to
 * change at 7am during an incident, from the console, without a shell and without root.
 * Six hours — the old cadence — is far too slow for a live phishing queue: a credential
 * harvester does its damage in minutes.
 *
 * Costs differ by an order of magnitude and the defaults reflect that:
 *   alerts   one Alert Center API call. Cheap. Polls hard.
 *   reports  GAM walks EVERY mailbox in the domain no matter how narrow the query, so this
 *            is minutes of work. Polls slowly.
 *
 * Concurrency: each job takes a row lock in WardenScheduleState. A tick that finds a job
 * already running skips it rather than starting a second GAM scan over the same mailboxes.
 * A lock older than `schedule.stuckAfterMinutes` is assumed to belong to a killed process
 * and is broken — otherwise one SIGKILL would stop that job forever, silently.
 */
import { PrismaClient } from '@prisma/client';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { sendMessage, reportDigest, alertDigest, reportsQuietNotice, type Severity } from '../src/lib/mailer';
import { shouldAlertQuiet } from '../src/lib/reports';
import { errText } from '../src/lib/errors';
import { isSetupComplete } from '../src/lib/setup';
import { setDefaultTz } from '../src/lib/time';

const prisma = new PrismaClient();

type JobKey = 'alerts' | 'reports' | 'loginscan' | 'knowbe4' | 'feeds' | 'hunt' | 'quarantine' | 'falcon' | 'verify' | 'studentvpn' | 'oauthgrants' | 'prunepii';

const FORCE = process.argv.includes('--force');
const ONLY = (() => {
  const i = process.argv.indexOf('--only');
  return i >= 0 ? (process.argv[i + 1] as JobKey | undefined) : undefined;
})();

function minutesSince(d: Date | null | undefined): number {
  return d ? (Date.now() - d.getTime()) / 60_000 : Number.POSITIVE_INFINITY;
}

/** Claim the lock, or report why we are not running. */
async function claim(key: JobKey, everyMinutes: number, stuckAfter: number) {
  const st = await prisma.wardenScheduleState.findUnique({ where: { key } });

  if (st?.running) {
    if (minutesSince(st.startedAt) < stuckAfter) return { ok: false as const, why: 'already running' };
    console.warn(`  ${key}: breaking a stuck lock (started ${st.startedAt?.toISOString()})`);
  }

  if (!FORCE && st && minutesSince(st.lastRunAt) < everyMinutes) {
    const wait = Math.ceil(everyMinutes - minutesSince(st.lastRunAt));
    return { ok: false as const, why: `not due for ${wait}m` };
  }

  await prisma.wardenScheduleState.upsert({
    where: { key },
    create: { key, running: true, startedAt: new Date() },
    update: { running: true, startedAt: new Date() }
  });
  return { ok: true as const };
}

async function release(key: JobKey, ok: boolean, detail: string) {
  await prisma.wardenScheduleState
    .update({
      where: { key },
      data: {
        running: false,
        startedAt: null,
        lastRunAt: new Date(),
        lastOk: ok,
        lastDetail: String(detail ?? '').slice(0, 500),
        runCount: { increment: 1 }
      }
    })
    .catch(() => undefined);
}

async function main() {
  // A fresh install has blank domains until the setup wizard is finished. Running now would
  // hand GAM an empty domain, so do nothing and say why.
  if (!(await isSetupComplete(prisma))) {
    console.log('setup not finished — nothing runs until an admin completes /setup');
    return;
  }
  const s = await getSettings(prisma);
  setDefaultTz(s.timezone); // digests in this run render in the district's local time
  const sch = s.schedule;
  const jobs: Array<{ key: JobKey; every: number; run: () => Promise<string> }> = [
    { key: 'alerts', every: sch.alertsMinutes, run: runAlerts },
    { key: 'reports', every: sch.reportsMinutes, run: runReports },
    { key: 'loginscan', every: sch.loginScanMinutes, run: runLoginScan },
    { key: 'knowbe4', every: sch.knowbe4Minutes, run: runKnowBe4 },
    { key: 'feeds', every: sch.feedsMinutes, run: runFeeds },
    // Hunt AFTER feeds, so a freshly-pulled indicator is matched on the same tick rather
    // than waiting for the next one.
    { key: 'hunt', every: sch.huntMinutes, run: runHunt },
    { key: 'quarantine', every: sch.quarantineMinutes ?? 10, run: runQuarantine },
    { key: 'falcon', every: sch.falconMinutes ?? 5, run: runFalcon },
    { key: 'verify', every: sch.verifyMinutes ?? 0, run: runVerify },
    { key: 'studentvpn', every: sch.studentVpnMinutes ?? 0, run: runStudentVpn },
    { key: 'oauthgrants', every: sch.oauthGrantsMinutes ?? 0, run: runOAuthGrants },
    { key: 'prunepii', every: sch.retentionMinutes ?? 1440, run: runPrunePii }
  ];

  for (const j of jobs) {
    if (ONLY && j.key !== ONLY) continue;
    if (!j.every || j.every <= 0) {
      console.log(`${j.key}: disabled (interval 0)`);
      continue;
    }
    const c = await claim(j.key, j.every, sch.stuckAfterMinutes);
    if (!c.ok) {
      console.log(`${j.key}: skipped — ${c.why}`);
      continue;
    }
    const t0 = Date.now();
    try {
      const detail = await j.run();
      const secs = Math.round((Date.now() - t0) / 1000);
      console.log(`${j.key}: ${detail} (${secs}s)`);
      await release(j.key, true, detail);
    } catch (e) {
      const msg = errText(e, 500);
      console.error(`${j.key}: FAILED — ${msg}`);
      await release(j.key, false, msg);
    }
  }
}

/**
 * Turn whatever a job returned into a detail string.
 *
 * Some jobs return a summary object, some a string, and some nothing at all — a job that
 * simply finishes is a success. Without this, an undefined return reached release() and
 * threw on .slice(), so the sign-in scan recorded FAILED every run while its work had
 * actually completed. A reporting layer that turns a success into a failure is worse than
 * no reporting.
 */
function summarise(r: unknown): string {
  if (r === undefined || r === null) return 'completed';
  if (typeof r === 'string') return r || 'completed';
  try { return JSON.stringify(r); } catch { return String(r); }
}

// ─── the jobs ────────────────────────────────────────────────────────────────

async function runAlerts(): Promise<string> {
  const before = await prisma.wardenAlert.count();
  const { run } = await import('./ingest-alerts');
  const r = await run();
  const s = await getSettings(prisma);

  // Tell somebody. An ingest that quietly files a leaked-password alert into a queue
  // nobody has open is the same failure as the reports that went to a dead tenant.
  if (s.schedule.notifyOnNewAlerts && r.newIds.length) {
    const wanted = s.schedule.notifySeverities
      .split(',')
      .map((x) => x.trim().toUpperCase())
      .filter(Boolean);
    const fresh = await prisma.wardenAlert.findMany({
      where: { alertId: { in: r.newIds }, state: 'NEW' },
      orderBy: { createTime: 'desc' }
    });
    const worth = fresh.filter((a) => !wanted.length || wanted.includes((a.severity ?? '').toUpperCase()));
    if (worth.length) {
      const msg = alertDigest(
        {
          total: r.stored,
          autoFiled: r.suppressed,
          items: worth.slice(0, 25).map((a) => ({
            type: a.type,
            who: a.email ?? a.recipient ?? 'unknown',
            detail:
              a.type === 'Suspicious login'
                ? [a.ip, a.ipOrg, a.ipClass === 'anonymizer' ? 'VPN / hosting' : a.ipClass]
                    .filter(Boolean)
                    .join('  ·  ')
                : (a.subject ?? a.bodySnippet ?? '').slice(0, 180),
            severity: (a.ipClass === 'anonymizer' || a.severity === 'HIGH'
              ? 'critical'
              : 'high') as Severity
          }))
        },
        s.consoleUrl
      );
      await sendMessage(s.mail, await notifyRecipients(prisma), msg, {
        throttleKey: `alerts-${worth.length}-${worth[0].alertId}`
      }).catch(() => undefined);
    }
  }
  const after = await prisma.wardenAlert.count();
  return `${r.stored} stored (+${after - before} new), ${r.suppressed} auto-filed, ${r.asReports} into reports`;
}

async function runReports(): Promise<string> {
  const { run } = await import('./ingest-reports');
  const r = await run();
  const s = await getSettings(prisma);

  if (s.schedule.notifyOnNewReports && r.created > 0) {
    const fresh = await prisma.wardenReport.findMany({
      where: { id: { in: r.createdIds } },
      orderBy: { reportedAt: 'desc' }
    });
    const groups = new Map<string, { subject: string; sender: string | null; count: number; hosts: Set<string> }>();
    for (const f of fresh) {
      const k = (f.originalSubject ?? f.originalSender ?? 'unparsed').slice(0, 70);
      const g = groups.get(k) ?? { subject: k, sender: f.originalSender, count: 0, hosts: new Set<string>() };
      g.count++;
      for (const h of JSON.parse(f.payloadHosts ?? '[]') as string[]) g.hosts.add(h);
      groups.set(k, g);
    }
    const msg = reportDigest(
      {
        created: r.created,
        suppressed: r.suppressed,
        campaigns: [...groups.values()]
          .sort((a, b) => b.count - a.count)
          .slice(0, 15)
          .map((g) => ({ subject: g.subject, sender: g.sender, count: g.count, hosts: [...g.hosts].slice(0, 4) }))
      },
      s.consoleUrl
    );
    await sendMessage(s.mail, await notifyRecipients(prisma), msg, {
      throttleKey: `reports-${r.created}-${r.createdIds[0] ?? ''}`
    }).catch(() => undefined);
  }

  // Quiet-volume watch: a misconfigured report address (a typo, a mailbox turned into a group)
  // returns a CLEAN zero no error check catches. Warn when nothing has arrived recently but the
  // district normally reports steadily. Once per day, DB-backed so the 30-min cadence does not
  // re-send and a restart does not reset it.
  const RECENT_DAYS = 3;
  const BASELINE_DAYS = 21;
  const now = Date.now();
  const recentCount = await prisma.wardenReport.count({
    where: { reportedAt: { gte: new Date(now - RECENT_DAYS * 86_400_000) } }
  });
  const baselineCount = await prisma.wardenReport.count({
    where: {
      reportedAt: {
        gte: new Date(now - (RECENT_DAYS + BASELINE_DAYS) * 86_400_000),
        lt: new Date(now - RECENT_DAYS * 86_400_000)
      }
    }
  });
  if (s.mail?.enabled && shouldAlertQuiet({ recentCount, baselineCount, baselineDays: BASELINE_DAYS })) {
    const today = new Date().toISOString().slice(0, 10);
    const last = await prisma.wardenSetting.findUnique({ where: { key: 'reports_quiet_last' } });
    if (last?.value !== today) {
      const res = await sendMessage(
        s.mail,
        await notifyRecipients(prisma),
        reportsQuietNotice(s.reports.addresses, RECENT_DAYS, s.consoleUrl)
      ).catch(() => ({ status: 'error' as const }));
      if (res.status === 'sent') {
        await prisma.wardenSetting.upsert({
          where: { key: 'reports_quiet_last' },
          create: { key: 'reports_quiet_last', value: today, updatedBy: 'reports-watch' },
          update: { value: today, updatedBy: 'reports-watch' }
        });
      }
    }
  }

  return `${r.created} new, ${r.backfilled} backfilled, ${r.suppressed} known-good`;
}

async function runLoginScan(): Promise<string> {
  const { run } = await import('./scan-logins');
  return summarise(await run());
}

async function runFeeds(): Promise<string> {
  const { run } = await import('./sync-feeds');
  return summarise(await run());
}

async function runHunt(): Promise<string> {
  const { run } = await import('./hunt-iocs');
  return summarise(await run());
}

async function runQuarantine(): Promise<string> {
  const { run } = await import('./sync-quarantine');
  return summarise(await run());
}

async function runFalcon(): Promise<string> {
  const { run } = await import('./sync-falcon');
  return summarise(await run());
}

async function runVerify(): Promise<string> {
  const { runVerifySignins } = await import('./verify-signins');
  return summarise(await runVerifySignins());
}

async function runStudentVpn(): Promise<string> {
  const { runQueueStudentVpn } = await import('./queue-student-vpn');
  return summarise(await runQueueStudentVpn());
}

async function runOAuthGrants(): Promise<string> {
  const { run } = await import('./scan-oauth-grants');
  return summarise(await run());
}

async function runKnowBe4(): Promise<string> {
  const { run } = await import('./sync-knowbe4');
  return summarise(await run());
}

async function runPrunePii(): Promise<string> {
  const { prunePii, pruneSummary } = await import('../src/lib/retention');
  const s = await getSettings(prisma);
  return pruneSummary(await prunePii(prisma, s.retention));
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
