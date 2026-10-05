/**
 * Mass-mail / exfil detector (warden-tick 'exfil' job).
 *
 * The delivery log is too heavy to scan tenant-wide, so this does not hunt blindly: it checks
 * the SENT mail of mailboxes ALREADY flagged by another detector (an open sign-in risk flag, a
 * new mail-capable OAuth grant, or a new external forward) and raises a high-severity risk flag
 * when a flagged account is now sending in bulk — the active-exfil/BEC shape. Read-only against
 * Google; the finding lands in the existing /risk queue so responders act in one place.
 *
 * Run manually:  sudo -u warden npx tsx scripts/scan-exfil.ts
 */
import { spawn } from 'node:child_process';
import { PrismaClient } from '@prisma/client';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { summarizeSent, isBlast, blastReasons } from '../src/lib/exfil';
import { sendMail, riskDigest } from '../src/lib/mailer';
import { errText } from '../src/lib/errors';

const prisma = new PrismaClient();

function gam(gamPath: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const c = spawn(gamPath, args, { stdio: ['ignore', 'pipe', 'ignore'] });
    c.stdout.on('data', (d) => chunks.push(Buffer.from(d)));
    c.on('error', reject);
    c.on('close', (code) =>
      code === 0 ? resolve(Buffer.concat(chunks).toString('utf8')) : reject(new Error(`gam ${args.slice(0, 4).join(' ')} exited ${code}`))
    );
  });
}

export async function run() {
  const s = await getSettings(prisma);
  const cfg = s.exfilWatch;
  if (!cfg.enabled) return 'disabled';
  if (!s.domains.staff) return 'no staff domain configured';

  // "External" is outside EVERY district domain, so both staff and student domains count as
  // internal when deciding whether a recipient is an outside address.
  const domains = [s.domains.staff.toLowerCase()];
  if (s.domains.students) domains.push(s.domains.students.toLowerCase());
  const suffixes = domains.map((d) => `@${d}`);

  // Suspect mailboxes come from the other detectors. A flagged account that is now blasting is
  // the confirmation; an unflagged one is out of scope here (the delivery log is too heavy).
  const openStates = ['NEW', 'INVESTIGATING'] as const;
  const [riskFlags, grantFlags, fwdItems] = await Promise.all([
    prisma.wardenRiskFlag.findMany({ where: { state: { in: openStates as never } }, select: { mailbox: true }, distinct: ['mailbox'] }),
    prisma.wardenGrantFlag.findMany({ where: { state: { in: openStates as never } }, select: { mailbox: true }, distinct: ['mailbox'] }),
    prisma.wardenForwardItem.findMany({ where: { external: true, active: true, state: { in: openStates as never } }, select: { mailbox: true }, distinct: ['mailbox'] })
  ]);
  const why = new Map<string, string>();
  for (const r of riskFlags) why.set(r.mailbox, 'an open sign-in risk flag');
  for (const g of grantFlags) if (!why.has(g.mailbox)) why.set(g.mailbox, 'a new mail-capable OAuth grant');
  for (const f of fwdItems) if (!why.has(f.mailbox)) why.set(f.mailbox, 'a new external forward/delegate');

  const suspects = [...why.keys()]
    .filter((mb) => suffixes.some((sfx) => mb.endsWith(sfx)))
    .slice(0, cfg.maxMailboxes || 50);

  const windowHours = cfg.windowHours || 6;
  const after = Math.floor((Date.now() - windowHours * 3600_000) / 1000);
  const windowStart = new Date(Date.now() - windowHours * 3600_000);
  const created: Array<{ mailbox: string; score: number; ts: Date; reasons: string[] }> = [];

  for (const mb of suspects) {
    // Already raised an exfil flag for this mailbox within the window? Don't re-raise the same fact.
    const dup = await prisma.wardenRiskFlag.findFirst({
      where: { mailbox: mb, ts: { gte: windowStart }, reasons: { contains: 'exfiltration' } }
    });
    if (dup) continue;

    let csv = '';
    try {
      // Gmail search has no hour granularity for newer_than, so bound the window with after:<epoch>.
      csv = await gam(s.gamPath, ['user', mb, 'print', 'messages', 'query', `in:sent after:${after}`, 'headers', 'To,Cc']);
    } catch (e) {
      console.error(`exfil: ${mb}: ${errText(e)}`);
      continue;
    }
    const summary = summarizeSent(csv, domains);
    if (!isBlast(summary, { maxMessages: cfg.maxMessages || 50, maxExternal: cfg.maxExternal || 25 })) continue;

    const reasons = blastReasons(summary, windowHours, why.get(mb) ?? 'a prior flag');
    const ts = new Date();
    try {
      await prisma.wardenRiskFlag.create({
        data: { mailbox: mb, ts, score: 95, reasons: JSON.stringify(reasons), suspicious: true }
      });
      created.push({ mailbox: mb, score: 95, ts, reasons });
      await prisma.wardenAudit
        .create({ data: { operator: 'scan-exfil', action: 'exfil_flag', target: mb, detail: `${summary.messages} sent, ${summary.external.length} external in ${windowHours}h` } })
        .catch(() => undefined);
    } catch {
      /* unique(mailbox, ts) — already flagged this instant */
    }
  }

  if (created.length && cfg.notify) {
    const msg = riskDigest(created, s.consoleUrl);
    const res = await sendMail(s.mail, await notifyRecipients(prisma), msg.subject, msg.text, {
      html: msg.html,
      throttleKey: `exfil-${new Date().toISOString().slice(0, 13)}`
    }).catch((e) => ({ status: 'error' as const, error: errText(e) }));
    if (res.status === 'error') console.error(`notification FAILED: ${res.error}`);
  }

  return `${suspects.length} suspect mailboxes checked, ${created.length} blasts flagged`;
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('scan-exfil')) {
  run()
    .catch((e) => {
      console.error(errText(e, 500));
      process.exitCode = 1;
    })
    .finally(() => prisma.$disconnect());
}
