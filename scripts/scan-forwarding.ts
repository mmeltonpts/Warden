/**
 * Forwarding & delegate watch (warden-tick 'forwardwatch' job).
 *
 * Read-only against Google: three passes over every mailbox for auto-forwarding, registered
 * forwarding addresses and delegates — the BEC persistence that survives a password reset. A
 * destination OUTSIDE the district is the exfil signal and goes to the review queue; internal
 * items are recorded but land BENIGN. Writes only to Warden's own database.
 *
 * Run manually:  sudo -u warden npx tsx scripts/scan-forwarding.ts
 */
import { spawn } from 'node:child_process';
import { PrismaClient } from '@prisma/client';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import {
  parseForwardingAddresses,
  parseDelegates,
  parseActiveForward,
  itemReasons,
  type PersistItem
} from '../src/lib/forwarding-watch';
import { sendMail, forwardDigest } from '../src/lib/mailer';
import { errText } from '../src/lib/errors';

const prisma = new PrismaClient();

function gam(gamPath: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    // stderr ignored (GAM writes a progress line per mailbox) — never left as an unread pipe.
    const c = spawn(gamPath, args, { stdio: ['ignore', 'pipe', 'ignore'] });
    c.stdout.on('data', (d) => chunks.push(Buffer.from(d)));
    c.on('error', reject);
    c.on('close', (code) =>
      code === 0 ? resolve(Buffer.concat(chunks).toString('utf8')) : reject(new Error(`gam ${args.join(' ')} exited ${code}`))
    );
  });
}

const keyOf = (i: { mailbox: string; kind: string; target: string }) => `${i.mailbox}\u0000${i.kind}\u0000${i.target}`;

export async function run() {
  const s = await getSettings(prisma);
  const cfg = s.forwardWatch;
  if (!cfg.enabled) return 'disabled';
  if (!s.domains.staff) return 'no staff domain configured';

  const domains = [s.domains.staff.toLowerCase()];
  if (cfg.scanStudents && s.domains.students) domains.push(s.domains.students.toLowerCase());
  const suffixes = domains.map((d) => `@${d}`);
  const inScope = (mb: string) => suffixes.some((sfx) => mb.endsWith(sfx));

  // Three read-only passes over every mailbox. A non-zero exit THROWS, so a failed pass is
  // never mistaken for "no forwarding found" (the empty-vs-failed trap).
  const [fwdCsv, delCsv, forwardTxt] = await Promise.all([
    gam(s.gamPath, ['all', 'users', 'print', 'forwardingaddresses']),
    gam(s.gamPath, ['all', 'users', 'print', 'delegates']),
    gam(s.gamPath, ['all', 'users', 'show', 'forward'])
  ]);

  const current: PersistItem[] = [
    ...parseForwardingAddresses(fwdCsv, domains),
    ...parseDelegates(delCsv, domains),
    ...parseActiveForward(forwardTxt, domains)
  ].filter((i) => inScope(i.mailbox));

  // The known items for this scope, to tell NEW from still-present. The table only holds
  // mailboxes that have (or had) forwarding/delegates, so it stays small.
  const known = (await prisma.wardenForwardItem.findMany()).filter((k) => inScope(k.mailbox));
  const knownByKey = new Map(known.map((k) => [keyOf(k), k]));

  const currentKeys = new Set<string>();
  const newExternal: PersistItem[] = [];
  const now = new Date();

  for (const it of current) {
    currentKeys.add(keyOf(it));
    const reasons = JSON.stringify(itemReasons(it));
    const prev = knownByKey.get(keyOf(it));
    if (!prev) {
      await prisma.wardenForwardItem
        .create({
          data: {
            mailbox: it.mailbox, kind: it.kind, target: it.target, external: it.external,
            detail: it.detail ?? null, reasons, firstSeen: now, lastSeen: now, active: true,
            state: it.external ? 'NEW' : 'BENIGN'
          }
        })
        .catch(() => undefined);
      if (it.external) newExternal.push(it);
    } else {
      // A previously-removed external item coming back is a fresh event worth surfacing again.
      const reappeared = !prev.active && it.external;
      await prisma.wardenForwardItem
        .update({
          where: { id: prev.id },
          data: {
            lastSeen: now, active: true, external: it.external, detail: it.detail ?? null, reasons,
            ...(reappeared ? { state: 'NEW' } : {})
          }
        })
        .catch(() => undefined);
      if (reappeared) newExternal.push(it);
    }
  }

  // Items no longer present → mark inactive (kept as history: removed persistence is evidence).
  const goneIds = known.filter((k) => k.active && !currentKeys.has(keyOf(k))).map((k) => k.id);
  if (goneIds.length) {
    await prisma.wardenForwardItem.updateMany({ where: { id: { in: goneIds } }, data: { active: false } });
  }

  if (newExternal.length && cfg.notify) {
    const msg = forwardDigest(
      newExternal.map((i) => ({ mailbox: i.mailbox, kind: i.kind, target: i.target, reasons: itemReasons(i) })),
      s.consoleUrl
    );
    const res = await sendMail(s.mail, await notifyRecipients(prisma), msg.subject, msg.text, {
      html: msg.html,
      throttleKey: `forward-${now.toISOString().slice(0, 13)}`
    }).catch((e) => ({ status: 'error' as const, error: errText(e) }));
    if (res.status === 'error') console.error(`notification FAILED: ${res.error}`);
  }

  const ext = current.filter((i) => i.external).length;
  return `${current.length} items (${ext} external), ${newExternal.length} new external, ${goneIds.length} removed`;
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('scan-forwarding')) {
  run()
    .catch((e) => {
      console.error(errText(e, 500));
      process.exitCode = 1;
    })
    .finally(() => prisma.$disconnect());
}
