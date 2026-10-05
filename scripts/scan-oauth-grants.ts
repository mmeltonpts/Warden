/**
 * OAuth-grant monitor (warden-tick 'oauthgrants' job).
 *
 * Read-only against Google: pulls the Admin token audit log for NEW authorizations and flags
 * any that can read or change mail to an app not on the allow-list — the token-takeover
 * persistence a password reset does not revoke and a mailbox sweep cannot see. Writes only to
 * Warden's own database.
 *
 * Run manually:  sudo -u warden npx tsx scripts/scan-oauth-grants.ts
 */
import { spawn } from 'node:child_process';
import { PrismaClient } from '@prisma/client';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { parseGrantEvents, selectGrantFlags, type GrantAllow } from '../src/lib/oauth-grants';
import { sendMail, grantDigest } from '../src/lib/mailer';
import { errText } from '../src/lib/errors';

const prisma = new PrismaClient();
const CURSOR = 'oauth_grants_cursor';

export async function run() {
  const s = await getSettings(prisma);
  const cfg = s.oauthWatch;
  if (!cfg.enabled) return 'disabled';
  if (!s.domains.staff) return 'no staff domain configured';

  const startedAt = new Date();
  const cur = await prisma.wardenSetting.findUnique({ where: { key: CURSOR } });
  // First run: bounded lookback so enabling the watch does not flag months of history at once.
  // After that an internal cursor advances to each run's start.
  const since = cur
    ? new Date(cur.value)
    : new Date(startedAt.getTime() - (cfg.lookbackHours || 2) * 3600_000);

  const domains = [s.domains.staff];
  if (cfg.scanStudents && s.domains.students) domains.push(s.domains.students);

  // The token report is tenant-wide; the domain list decides what is KEPT, not what is
  // fetched. stderr is ignored (never left as an unread pipe), and a non-zero exit THROWS, so
  // a failed fetch can never masquerade as a clean window (the empty-vs-failed trap).
  const csv = await new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const child = spawn(
      s.gamPath,
      ['report', 'token', 'start', since.toISOString(), 'event', 'authorize'],
      { stdio: ['ignore', 'pipe', 'ignore'] }
    );
    child.stdout.on('data', (d) => chunks.push(Buffer.from(d)));
    child.on('error', reject);
    child.on('close', (code) =>
      code === 0 ? resolve(Buffer.concat(chunks).toString('utf8')) : reject(new Error(`gam report token exited ${code}`))
    );
  });

  const events = parseGrantEvents(csv, domains);
  const allow: GrantAllow = {
    clientIds: new Set((cfg.allowClientIds ?? []).map((x) => x.trim()).filter(Boolean)),
    namePatterns: (cfg.allowNames ?? []).map((x) => x.trim()).filter(Boolean)
  };
  const flags = selectGrantFlags(events, allow);

  // Persist. The unique (mailbox, clientId, ts) drops a grant already recorded by an
  // overlapping earlier run, so the cursor can overlap safely.
  const created: typeof flags = [];
  for (const f of flags) {
    try {
      await prisma.wardenGrantFlag.create({
        data: {
          mailbox: f.mailbox,
          ts: f.ts,
          appName: f.appName,
          clientId: f.clientId,
          clientType: f.clientType || null,
          scopes: JSON.stringify(f.scopes),
          ip: f.ip ?? null,
          fanOut: f.fanOut,
          reasons: JSON.stringify(f.reasons)
        }
      });
      created.push(f);
    } catch {
      /* unique(mailbox, clientId, ts) — already flagged by an earlier overlapping run */
    }
  }

  // Advance the cursor only after the work above committed.
  await prisma.wardenSetting.upsert({
    where: { key: CURSOR },
    create: { key: CURSOR, value: startedAt.toISOString(), updatedBy: 'scan-oauth-grants' },
    update: { value: startedAt.toISOString(), updatedBy: 'scan-oauth-grants' }
  });

  // Notify AFTER the cursor is recorded, so a relay outage cannot re-scan the same window.
  if (created.length && cfg.notify) {
    const msg = grantDigest(created, s.consoleUrl);
    const res = await sendMail(s.mail, await notifyRecipients(prisma), msg.subject, msg.text, {
      html: msg.html,
      throttleKey: `grants-${startedAt.toISOString().slice(0, 13)}`
    }).catch((e) => ({ status: 'error' as const, error: errText(e) }));
    if (res.status === 'error') console.error(`notification FAILED: ${res.error}`);
  }

  return `${events.length} authorize events, ${flags.length} mail-capable not allow-listed, ${created.length} new`;
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('scan-oauth-grants')) {
  run()
    .catch((e) => {
      console.error(errText(e, 500));
      process.exitCode = 1;
    })
    .finally(() => prisma.$disconnect());
}
