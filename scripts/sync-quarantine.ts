/**
 * Read admin quarantine from the Gmail delivery log.
 *
 *   sudo -u warden npx tsx scripts/sync-quarantine.ts [--hours N]
 *
 * Quarantined mail never reaches a mailbox, so no scope can see it. See WardenQuarantine.
 *
 * COST CONTROL — learned by running a 24-hour pull out of a 4 GB heap:
 *   - GAM writes to a file; the file is streamed, never read into memory.
 *   - Only rows containing `admin_quarantine_info` are parsed. ~99.9% are skipped by indexOf.
 *   - Incremental: a cursor records how far the last successful run got, and each run asks
 *     only for what is new. The window overlaps the previous one because Google writes the
 *     log minutes behind delivery; the unique (msgId, recipient) key absorbs the overlap.
 *
 * Read-only against Google. Release and deny stay in the Admin console — there is no API.
 */
import { PrismaClient } from '@prisma/client';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { getSettings } from '../src/lib/settings';
import { scanGmailLogFile, type GmailLogEvent } from '../src/lib/gmaillog';
import { LOG_DIR } from '../src/lib/gam';
import { sendMail, render } from '../src/lib/mailer';
import { errText } from '../src/lib/errors';

const prisma = new PrismaClient();
const CURSOR = 'quarantine_cursor';
const OVERLAP_MIN = 45;
const MAX_WINDOW_H = 6;

function argHours(): number | null {
  const i = process.argv.indexOf('--hours');
  const n = i >= 0 ? Number(process.argv[i + 1]) : NaN;
  return Number.isFinite(n) && n > 0 ? n : null;
}

export async function run() {
  const s = await getSettings(prisma);
  const now = new Date();

  const cur = await prisma.wardenSetting.findUnique({ where: { key: CURSOR } });
  const forced = argHours();
  let start = forced
    ? new Date(now.getTime() - forced * 3_600_000)
    : cur
      ? new Date(new Date(cur.value).getTime() - OVERLAP_MIN * 60_000)
      : new Date(now.getTime() - MAX_WINDOW_H * 3_600_000);
  // Never ask for more than MAX_WINDOW_H unless forced — a stale cursor after an outage
  // must not become a 3-day pull that takes the tick down.
  if (!forced && now.getTime() - start.getTime() > MAX_WINDOW_H * 3_600_000) {
    start = new Date(now.getTime() - MAX_WINDOW_H * 3_600_000);
  }

  await mkdir(LOG_DIR, { recursive: true });
  const file = path.join(LOG_DIR, `quarantine-${now.getTime()}.csv`);

  const exit = await new Promise<number>((resolve) => {
    const out = createWriteStream(file);
    const c = spawn(s.gamPath, ['report', 'gmail', 'start', start.toISOString(), 'end', now.toISOString()], {
      // stderr ignored rather than piped-and-unread: see CLAUDE.md on GAM stderr deadlocks.
      stdio: ['ignore', 'pipe', 'ignore']
    });
    c.stdout.pipe(out);
    c.on('error', () => out.end(() => resolve(-1)));
    c.on('close', (code) => out.end(() => resolve(code ?? -1)));
  });

  // Indicators to match against. Loaded once per run.
  const iocs = await prisma.wardenIoc.findMany({ select: { kind: true, value: true } });
  const senders = iocs.filter((i) => i.kind === 'SENDER').map((i) => i.value.toLowerCase());
  const lures = iocs.filter((i) => i.kind === 'LURE_STRING').map((i) => i.value.toLowerCase());
  const hosts = new Set(iocs.filter((i) => i.kind === 'PAYLOAD_HOST').map((i) => i.value.toLowerCase()));

  const fresh: GmailLogEvent[] = [];
  let scan = { rows: 0, matched: 0 };
  try {
    scan = await scanGmailLogFile(file, 'admin_quarantine_info', async (e) => {
      if (!e.quarantined || !e.recipient) return;
      const q = e.rules.find((r) => r.quarantine);

      let iocHit: string | null = null;
      const from = (e.sender ?? '').toLowerCase();
      const subj = (e.subject ?? '').toLowerCase();
      iocHit =
        senders.find((x) => from && from.includes(x)) ??
        lures.find((x) => subj.includes(x)) ??
        e.linkDomains.find((d) => hosts.has(d.toLowerCase())) ??
        null;
      if (!iocHit && e.linkDomains.length) {
        const f = await prisma.wardenFeedIoc.findFirst({
          where: { host: { in: e.linkDomains.map((d) => d.toLowerCase()) } },
          select: { host: true, source: true }
        });
        if (f) iocHit = `${f.host} (${f.source})`;
      }

      const existing = await prisma.wardenQuarantine.findUnique({
        where: { msgId_recipient: { msgId: e.msgId, recipient: e.recipient } }
      });
      if (existing) return;
      await prisma.wardenQuarantine.create({
        data: {
          msgId: e.msgId,
          recipient: e.recipient.toLowerCase(),
          sender: e.sender,
          subject: e.subject,
          senderIp: e.senderIp,
          attachments: e.attachments,
          linkDomains: JSON.stringify(e.linkDomains),
          rules: JSON.stringify(e.rules),
          ruleName: q?.name ?? null,
          matched: q?.matched.join(', ') || null,
          heldAt: e.time,
          iocHit
        }
      });
      fresh.push({ ...e });
    });
  } finally {
    await unlink(file).catch(() => undefined);
  }

  // Advance the cursor only on a clean GAM run. A failed pull must be retried, not skipped.
  if (exit === 0 || exit === 60) {
    await prisma.wardenSetting.upsert({
      where: { key: CURSOR },
      create: { key: CURSOR, value: now.toISOString(), updatedBy: 'sync-quarantine' },
      update: { value: now.toISOString(), updatedBy: 'sync-quarantine' }
    });
  }

  console.log(
    `window ${start.toISOString().slice(0, 16)}Z..${now.toISOString().slice(0, 16)}Z: ` +
      `${scan.rows} log rows, ${scan.matched} quarantine rows, ${fresh.length} new holds (GAM exit ${exit})`
  );

  if (fresh.length && s.quarantine?.notify !== false) {
    const withIoc = fresh;
    const { text, html } = render({
      title: `${fresh.length} message${fresh.length === 1 ? '' : 's'} held in quarantine`,
      lede:
        'Your content-compliance rules held these before delivery. Nothing reached a mailbox. ' +
        'Release or deny in the Admin console; Warden cannot, because Google has no API for it.',
      blocks: [
        {
          items: withIoc.slice(0, 20).map((e) => ({
            title: e.subject ?? '(no subject)',
            meta: `${e.sender ?? '?'} → ${e.recipient} · ${e.rules.find((r) => r.quarantine)?.name ?? ''}`,
            detail: e.rules.find((r) => r.quarantine)?.matched.join(', ') || undefined,
            severity: 'high' as const
          }))
        }
      ],
      cta: { label: 'Open quarantine in Warden', href: `${s.consoleUrl}/quarantine` },
      baseUrl: s.consoleUrl
    });
    // ADMIN accounts only — NOT notifyRecipients(), which includes responders, analysts and
    // free-text addresses. Held mail includes correspondence nobody else should read.
    const admins = (await prisma.wardenUser.findMany({ where: { role: 'ADMIN', disabled: false }, select: { email: true } })).map((a) => a.email);
    const r = await sendMail(s.mail, admins, `Warden: ${fresh.length} held in quarantine`, text, {
      html,
      throttleKey: `quarantine-${now.toISOString().slice(0, 15)}`
    }).catch((e) => ({ status: 'error' as const, error: errText(e) }));
    if (r.status === 'error') console.error(`notification FAILED: ${'error' in r ? r.error : ''}`);
  }

  if (exit !== 0 && exit !== 60) throw new Error(`gam report gmail exited ${exit}; cursor not advanced`);
  return `${fresh.length} new holds (${scan.rows} log rows)`;
}

if (process.argv[1]?.includes('sync-quarantine')) {
  run()
    .catch((e) => { console.error(errText(e, 500)); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}
