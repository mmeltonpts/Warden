/**
 * Preflight — verify every external dependency Warden has, for real.
 *
 *   sudo -u warden npx tsx scripts/preflight.ts          # checks only
 *   sudo -u warden npx tsx scripts/preflight.ts --send   # also sends a live test email
 *
 * Every check here exists because the same failure is silent in production: the SMTP
 * relay accepts the config and rejects the session, a KnowBe4 token saves but is
 * unauthorised, a report address is a typo, GAM's token expires overnight.
 *
 * The PhishER gap lasted six months precisely because nothing ever asserted that the
 * far end was listening. This is that assertion.
 *
 * Read-only against Google unless --send is passed.
 */
import { PrismaClient } from '@prisma/client';
import { spawn } from 'node:child_process';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { sendMail } from '../src/lib/mailer';
import { kb4Health } from '../src/lib/knowbe4';

const prisma = new PrismaClient();
const SEND = process.argv.includes('--send');

type State = 'ok' | 'fail' | 'warn' | 'skip';
const rows: Array<{ state: State; name: string; detail: string }> = [];
const add = (state: State, name: string, detail: string) => rows.push({ state, name, detail });

function gam(gamPath: string, args: string[], timeoutMs = 90_000): Promise<string> {
  return new Promise((resolve) => {
    let out = '';
    const c = spawn(gamPath, args);
    const t = setTimeout(() => c.kill('SIGKILL'), timeoutMs);
    c.stdout.on('data', (d) => (out += d));
    c.stderr.on('data', (d) => (out += d));
    c.on('error', (e) => resolve(`ERROR: ${e.message}`));
    c.on('close', () => {
      clearTimeout(t);
      resolve(out);
    });
  });
}

async function main() {
  const s = await getSettings(prisma);

  // ── database ───────────────────────────────────────────────────────────────
  const [users, reports, baselines] = await Promise.all([
    prisma.wardenUser.count({ where: { disabled: false } }),
    prisma.wardenReport.count(),
    prisma.wardenBaseline.count()
  ]);
  add('ok', 'Database', `${users} active users, ${reports} reports, ${baselines} baselines`);

  // ── GAM authentication ─────────────────────────────────────────────────────
  const dom = await gam(s.gamPath, ['info', 'domain']);
  if (/ERROR|No Client Access|Not Found/i.test(dom) || !dom.trim()) {
    add('fail', 'GAM auth', dom.split('\n').filter(Boolean).slice(-2).join(' ').slice(0, 160));
  } else {
    const m = dom.match(/Customer ID:\s*(\S+)/i);
    add('ok', 'GAM auth', `domain reachable${m ? `, customer ${m[1]}` : ''}`);
  }

  // ── report addresses ───────────────────────────────────────────────────────
  // A bare domain (phisher.knowbe4.com) is a historical backfill target, not a group.
  const addresses = s.reports.addresses.split(',').map((a) => a.trim()).filter(Boolean);
  for (const a of addresses) {
    if (!a.includes('@')) {
      add('warn', `Report target ${a}`, 'external domain — backfill only, remove once history is ingested');
      continue;
    }
    const g = await gam(s.gamPath, ['info', 'group', a]);
    if (/Does not exist|ERROR|not found/i.test(g)) {
      add('fail', `Report group ${a}`, 'does not exist — the PAB would be delivering nowhere');
    } else {
      const members = (g.match(/Members:\s*(\d+)/i) ?? [])[1];
      const post = /whoCanPostMessage:\s*(\S+)/i.exec(g)?.[1] ?? '';
      // A group that only accepts internal posts silently drops nothing here, but a
      // restricted group is worth seeing before someone wonders where a report went.
      const open = !post || /ANYONE_CAN_POST|ALL_IN_DOMAIN_CAN_POST/i.test(post);
      add(open ? 'ok' : 'warn', `Report group ${a}`,
        `exists${members ? `, ${members} member(s)` : ''}${post ? `, post: ${post}` : ''}`);
    }
  }

  // Are reports actually LANDING at the new address, or still only at the old one?
  const byTarget = await prisma.wardenReport.groupBy({
    by: ['reportedTo'],
    _count: { _all: true },
    _max: { reportedAt: true }
  });
  if (byTarget.length === 0) {
    add('warn', 'Report flow', 'no reports ingested yet — run scripts/ingest-reports.ts');
  } else {
    for (const t of byTarget.sort((a, b) => b._count._all - a._count._all).slice(0, 6)) {
      const last = t._max.reportedAt;
      const ageDays = last ? Math.floor((Date.now() - last.getTime()) / 86_400_000) : null;
      const silent = ageDays !== null && ageDays > 7;
      add(silent ? 'warn' : 'ok', `Reports to ${t.reportedTo || '(unparsed)'}`,
        `${t._count._all} report(s), last ${last ? last.toISOString().slice(0, 10) : 'never'}` +
          (silent ? ` — ${ageDays}d silent` : ''));
    }
  }

  // ── SMTP relay ─────────────────────────────────────────────────────────────
  const rcpt = await notifyRecipients(prisma);
  if (!s.mail.enabled) {
    add('fail', 'SMTP relay', 'notifications DISABLED in Settings — nothing will ever send');
  } else if (!rcpt.length) {
    add('fail', 'SMTP relay', 'enabled but no recipients configured and no active admins');
  } else if (!SEND) {
    add('skip', 'SMTP relay',
      `${s.mail.host}:${s.mail.port} as ${s.mail.from} to ${rcpt.join(', ')} — pass --send to prove it`);
  } else {
    const body =
      'This is a Warden preflight test.\n\n' +
      'If you are reading this, the Google Workspace SMTP relay accepts mail from this\n' +
      `host's public egress IP and permits ${s.mail.from} as a sender.\n\n` +
      `Console: ${s.consoleUrl}\n\nNo action needed.`;
    const r = await sendMail(s.mail, rcpt, 'Warden: preflight test', body, {
      throttleKey: `preflight-${Date.now()}`
    });
    if (r.status === 'sent') add('ok', 'SMTP relay', `delivered to ${rcpt.join(', ')}`);
    else add('fail', 'SMTP relay', `${r.status}${r.error ? `: ${r.error}` : ''}`);
  }

  // ── KnowBe4 ────────────────────────────────────────────────────────────────
  if (!s.knowbe4.enabled) {
    add('skip', 'KnowBe4', 'disabled in Settings');
  } else {
    const h = await kb4Health(s.knowbe4);

    const rep = h.reporting;
    add(rep.status === 'ok' ? 'ok' : 'fail', 'KnowBe4 Reporting API',
      rep.status === 'ok'
        ? `authorised at ${s.knowbe4.reportingBaseUrl}`
        : `${rep.status}${rep.httpStatus ? ` (HTTP ${rep.httpStatus})` : ''}` +
          `${rep.error ? ` ${rep.error}` : ''}` +
          ' — a KCM/Compliance-Manager key returns exactly this; the key must be minted' +
          ' from KSAT Account Settings > API, and its JWT scope must not read "kcm"');

    const ue = h.userEvents;
    add(ue.status === 'ok' ? 'ok' : ue.status === 'disabled' ? 'skip' : 'fail',
      'KnowBe4 User Events',
      ue.status === 'ok'
        ? `authorised at ${s.knowbe4.userEventsUrl}`
        : ue.status === 'disabled'
          ? 'push disabled in Settings'
          : `${ue.status}${ue.httpStatus ? ` (HTTP ${ue.httpStatus})` : ''}${ue.error ? `: ${ue.error}` : ''}`);

    // Informational, NOT a failure. The published User Events spec says of `event_type`:
    // "If the event type does not already exist, the value entered here will be used to
    // create a new event type." Corroborated by Cortex XSOAR's KMSAT pack, which ships no
    // create-event-type command at all, and by the console having no such UI. An earlier
    // version of this check reported "fail" here and would have sent an admin hunting for
    // a setting that does not exist.
    if (h.eventTypes) {
      const { defined, missing } = h.eventTypes;
      add('ok', 'KnowBe4 event types',
        missing.length
          ? `${defined.length} defined in KSAT; ${missing.length} Warden type(s) will be auto-created on first push`
          : `all ${defined.length} Warden types already defined`);
    }
  }

  // ── destructive gate ───────────────────────────────────────────────────────
  const destructive = process.env.WARDEN_ALLOW_DESTRUCTIVE === '1';
  add(destructive ? 'ok' : 'warn', 'Sweep gate',
    destructive
      ? 'ENABLED — sweeps will execute'
      : 'disabled — scope and verify work, every sweep is refused');

  // ── output ─────────────────────────────────────────────────────────────────
  const MARK: Record<State, string> = { ok: ' ok ', fail: 'FAIL', warn: 'warn', skip: 'skip' };
  const w = Math.max(...rows.map((r) => r.name.length));
  console.log('');
  for (const r of rows) console.log(`  [${MARK[r.state]}]  ${r.name.padEnd(w)}  ${r.detail}`);
  const fails = rows.filter((r) => r.state === 'fail').length;
  const warns = rows.filter((r) => r.state === 'warn').length;
  console.log(`\n  ${fails} failing, ${warns} warning, ${rows.length - fails - warns} ok/skipped\n`);
  if (fails) process.exitCode = 1;
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
