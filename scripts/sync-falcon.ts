/**
 * Mirror CrowdStrike Falcon alerts into Warden.
 *
 *   sudo -u warden npx tsx scripts/sync-falcon.ts [--days N]
 *
 * Read-only against Falcon. Incremental on updated_timestamp, so status changes made in the
 * Falcon console (closed, in progress) flow back here too.
 */
import { PrismaClient } from '@prisma/client';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { falconClient } from '../src/lib/crowdstrike';
import { toEdrRow, severityRank, userAtAlert, usualUser, type FalconAlertRaw, type EdrRow } from '../src/lib/falcon-alerts';
import { sendMail, render } from '../src/lib/mailer';
import { errText } from '../src/lib/errors';
import { refreshToolSnapshot } from '../src/lib/remote-tools-sync';

const prisma = new PrismaClient();
const CURSOR = 'falcon_cursor';
const OVERLAP_MIN = 10;

function argDays(): number | null {
  const i = process.argv.indexOf('--days');
  const n = i >= 0 ? Number(process.argv[i + 1]) : NaN;
  return Number.isFinite(n) && n > 0 ? n : null;
}

export async function run() {
  const s = await getSettings(prisma);
  const cfg = s.crowdstrike;
  if (!cfg.enabled) return 'disabled';
  const fc = await falconClient(cfg);
  const minRank = severityRank(cfg.minSeverity || 'Low');

  const cur = await prisma.wardenSetting.findUnique({ where: { key: CURSOR } });
  const days = argDays();
  const since = days
    ? new Date(Date.now() - days * 86_400_000)
    : cur
      ? new Date(new Date(cur.value).getTime() - OVERLAP_MIN * 60_000)
      : new Date(Date.now() - 30 * 86_400_000);
  const startedAt = new Date();

  const filter = `updated_timestamp:>'${since.toISOString()}'`;
  const ids: string[] = [];
  for (let offset = 0; offset < 10_000; offset += 500) {
    const page = await fc.alertIds(filter, offset);
    ids.push(...page.ids);
    if (page.ids.length < 500 || ids.length >= page.total) break;
  }

  const known = new Set((await prisma.wardenBaseline.findMany({ select: { mailbox: true } })).map((b) => b.mailbox));
  const iocs = await prisma.wardenIoc.findMany({
    where: { kind: { in: ['PAYLOAD_HOST', 'IP'] } },
    select: { value: true }
  });

  let stored = 0;
  let skipped = 0;
  const fresh: Array<EdrRow & { iocHit: string | null }> = [];

  const domains = { staff: s.domains.staff, students: s.domains.students };
  const raws = (await fc.alerts(ids)) as FalconAlertRaw[];

  // Alerts that ran as SYSTEM name no person. Ask Falcon who was signed in to those hosts —
  // one batched call per run, not one per alert.
  const needLogin = [
    ...new Set(
      raws
        .filter((r) => !toEdrRow(r, domains, known).mailbox && r.device?.device_id)
        .map((r) => r.device!.device_id!)
    )
  ];
  const logins = needLogin.length ? await fc.loginHistory(needLogin).catch(() => new Map()) : new Map();

  for (const raw of raws) {
    let row: EdrRow & { userSource: string | null; loginUser: string | null; loginAt: Date | null } = {
      ...toEdrRow(raw, domains, known),
      userSource: null,
      loginUser: null,
      loginAt: null
    };
    if (row.mailbox) {
      row.userSource = 'alert';
    } else if (row.deviceId && logins.has(row.deviceId)) {
      const who = userAtAlert(logins.get(row.deviceId)!, row.createdAt, domains, known);
      if (who) {
        row = { ...row, mailbox: who.mailbox, userSource: 'host-login', loginUser: who.loginUser, loginAt: who.loginAt };
      } else {
        const usual = usualUser(logins.get(row.deviceId)!, domains, known);
        if (usual) row = { ...row, mailbox: usual, userSource: 'host-usual' };
      }
    }
    const hosts: string[] = JSON.parse(row.hosts);
    const tree = [row.cmdline, row.parentCmd, row.grandCmd].join(' ').toLowerCase();

    let iocHit: string | null =
      iocs.find((i) => hosts.includes(i.value.toLowerCase()) || tree.includes(i.value.toLowerCase()))?.value ?? null;
    if (!iocHit && hosts.length) {
      const f = await prisma.wardenFeedIoc.findFirst({ where: { host: { in: hosts } }, select: { host: true, source: true } });
      if (f) iocHit = `${f.host} (${f.source})`;
    }

    // Below the floor is dropped — unless it touches a known indicator or is an OverWatch
    // lead. Those are kept whatever Falcon called their severity.
    if (severityRank(row.severityName) < minRank && !iocHit && row.product !== 'overwatch') {
      skipped++;
      continue;
    }

    const existing = await prisma.wardenEdrAlert.findUnique({
      where: { compositeId: row.compositeId },
      select: { compositeId: true }
    });
    await prisma.wardenEdrAlert.upsert({
      where: { compositeId: row.compositeId },
      create: { ...row, iocHit },
      update: { ...row, iocHit }
    });
    stored++;
    if (!existing) fresh.push({ ...row, iocHit });
  }

  await prisma.wardenSetting.upsert({
    where: { key: CURSOR },
    create: { key: CURSOR, value: startedAt.toISOString(), updatedBy: 'sync-falcon' },
    update: { value: startedAt.toISOString(), updatedBy: 'sync-falcon' }
  });

  // Page on what needs a human, and say plainly whether Falcon BLOCKED it or only DETECTED
  // it. "Detected" means it ran — rogue ScreenConnect ran detected-only for three days.
  const urgent = days ? [] : fresh.filter((r) => r.severity >= 70 || r.product === 'overwatch' || r.iocHit);
  if (urgent.length && cfg.notify !== false) {
    const { text, html } = render({
      title: `${urgent.length} endpoint detection${urgent.length === 1 ? '' : 's'} need a look`,
      lede: 'From CrowdStrike Falcon. "Detected only" means the activity was allowed to run.',
      blocks: [
        {
          items: urgent.slice(0, 20).map((r) => ({
            title: `${r.hostname ?? '?'} — ${r.displayName ?? r.name ?? 'alert'}`,
            meta:
              `${r.severityName} · ${r.blocked ? 'BLOCKED' : 'DETECTED ONLY — it ran'}` +
              `${r.mailbox ? ` · ${r.mailbox}` : ''}${r.product === 'overwatch' ? ' · OverWatch' : ''}`,
            detail:
              [r.iocHit ? `Matches indicator: ${r.iocHit}` : null, (JSON.parse(r.hosts) as string[]).slice(0, 4).join(', ') || null]
                .filter(Boolean)
                .join(' · ') || undefined,
            severity: (r.severity >= 90 ? 'critical' : 'high') as 'critical' | 'high'
          }))
        }
      ],
      cta: { label: 'Open endpoint detections', href: `${s.consoleUrl}/edr` },
      baseUrl: s.consoleUrl
    });
    const res = await sendMail(
      s.mail,
      await notifyRecipients(prisma),
      `Warden: ${urgent.length} endpoint detection${urgent.length === 1 ? '' : 's'}`,
      text,
      { html, throttleKey: `edr-${startedAt.toISOString().slice(0, 15)}` }
    ).catch((e) => ({ status: 'error' as const, error: errText(e) }));
    if (res.status === 'error') console.error(`notification FAILED: ${'error' in res ? res.error : ''}`);
  }

  console.log(
    `since ${since.toISOString().slice(0, 16)}Z: ${ids.length} updated in Falcon, ${stored} stored, ` +
      `${skipped} below the severity floor, ${fresh.length} new, ${urgent.length} urgent`
  );
  // Remote-access tool inventory: hourly, in the background, so the Endpoints tab is instant.
  const toolsResult = await refreshToolSnapshot(prisma, cfg);
  console.log(toolsResult);
  return `${fresh.length} new, ${urgent.length} urgent; ${toolsResult}`;
}

if (process.argv[1]?.includes('sync-falcon')) {
  run()
    .catch((e) => { console.error(errText(e, 500)); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}
