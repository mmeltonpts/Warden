/**
 * Hunt stored indicators across the district.
 *
 *   sudo -u warden npx tsx scripts/hunt-iocs.ts [--days N] [--dry]
 *
 * Warden has been recording indicators since day one and never went looking with them.
 * This is the part that looks.
 *
 * THE SPLIT THAT MAKES THIS WORK
 *
 * Indicators are not equally searchable, and pretending otherwise wastes hours:
 *
 *   SENDER, LURE_STRING   -> GAM domain scope. Gmail indexes From: and body text exactly,
 *                            so these hit reliably. This is the expensive half — GAM walks
 *                            every mailbox — but it is the half that finds mail nobody
 *                            reported.
 *
 *   PAYLOAD_HOST, feeds   -> matched LOCALLY against hosts already extracted from reported
 *                            messages. Gmail CANNOT match a domain inside a message body: a
 *                            scan for a domain provably present returned zero. Searching
 *                            Gmail for a payload host is a query that structurally cannot
 *                            hit, and doing it for 100,000 feed URLs would be 100,000 of
 *                            them.
 *
 *   IP                    -> matched against sign-in events, where addresses are a column.
 *
 * NOTHING IS SWEPT. This job is read-only by design. `assertSweepSafe()` refuses
 * sender-only sweeps because a sweep of one compromised partner-district account would have
 * destroyed 51 live IEP messages — and that account is in the SENDER list right now. A hunt
 * that swept its own matches would have deleted them. A human reads the preview and decides.
 */
import { PrismaClient } from '@prisma/client';
import { spawn } from 'node:child_process';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { sendMail, render, defangUrl } from '../src/lib/mailer';
import { huntTerms, attribute, UNATTRIBUTED, huntExclusions, isOwnTraffic } from '../src/lib/hunt';

const prisma = new PrismaClient();

const DRY = process.argv.includes('--dry');
function argDays(): number {
  const i = process.argv.indexOf('--days');
  const n = i >= 0 ? Number(process.argv[i + 1]) : NaN;
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 30;
}

/** stderr inherited, never an unread pipe — see CLAUDE.md. */
function gam(gamPath: string, args: string[], timeoutMs = 1_800_000): Promise<string> {
  return new Promise((resolve) => {
    let out = '';
    const c = spawn(gamPath, args, { stdio: ['ignore', 'pipe', 'inherit'] });
    const t = setTimeout(() => c.kill('SIGKILL'), timeoutMs);
    c.stdout.on('data', (d) => (out += d));
    c.on('error', () => resolve(out));
    c.on('close', () => { clearTimeout(t); resolve(out); });
  });
}

function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

async function record(h: {
  source: string; iocValue: string; kind: string; surface: string;
  subject?: string | null; mailbox?: string | null; detail?: string | null; reportId?: string | null;
}): Promise<boolean> {
  // Same indicator, same surface, same mailbox = already known. Re-recording it every run
  // would turn a standing condition into a stream of "new" findings.
  const dupe = await prisma.wardenIocHit.findFirst({
    where: { iocValue: h.iocValue, surface: h.surface, mailbox: h.mailbox ?? null, subject: h.subject ?? null }
  });
  if (dupe) return false;
  if (!DRY) await prisma.wardenIocHit.create({ data: h as never });
  return true;
}

export async function run() {
  const s = await getSettings(prisma);
  const days = argDays();
  const fresh: Array<{ ioc: string; kind: string; surface: string; where: string; what: string }> = [];

  // ── 1. curated senders and lure strings: a real Gmail hunt ────────────────
  const searchable = await prisma.wardenIoc.findMany({
    where: { kind: { in: ['SENDER', 'LURE_STRING'] } },
    select: { value: true, kind: true, firstSeen: true, addedAt: true }
  });

  /**
   * A compromised account is hostile for a few days and is the real person either side of
   * that. The first dry run matched "Weather Protocol for New Prairie", "Cross Country" and
   * "2026 New Prairie Invite" against a compromised athletic director — genuine athletics
   * mail from a genuine colleague, indistinguishable from the attack by sender alone.
   *
   * This is the sweep lesson in a new place: a from:-only scope of one partner-district
   * account would have destroyed 51 live IEP messages, and assertSweepSafe refuses it. A
   * hunt does not delete, but an unscoped one buries the real hits — 1,981 findings nobody
   * reads is the same outcome as no findings at all.
   *
   * firstSeen is nullable, so it falls back to addedAt rather than to an unscoped from:.
   * Every sender term carries a date window; there is no path that omits one. The query
   * building and the attribution both live in src/lib/hunt.ts, with tests.
   */
  console.log(`hunting ${searchable.length} searchable indicators across ${s.domains.staff} (${days}d)`);

  // One query, not one per indicator. GAM walks every mailbox per invocation, so N queries
  // would be N full passes over 1,300 mailboxes.
  const terms = huntTerms(searchable, s.hunt.senderWindowDays);
  if (terms.length) {
    // NOTE: newer_than ANDs with the whole OR group, so it bounds the sender windows too.
    // An indicator first seen longer ago than --days can therefore never match, by design:
    // the flag is the outer limit of the hunt. Widen --days to reach older indicators.
    const own = { wardenFrom: s.mail?.from, protectedSubjects: s.protectedSubjects ?? [] };
    const query = `(${terms.join(' OR ')}) newer_than:${days}d in:anywhere ${huntExclusions(own)}`.trim();
    const csv = await gam(s.gamPath, [
      'domains_ns', s.domains.staff, 'print', 'messages', 'query', query, 'headers', 'From,To,Subject,Date'
    ]);
    const lines = csv.split(/\r?\n/).filter(Boolean);
    if (lines.length > 1) {
      const header = splitCsv(lines[0]);
      const col = (n: string) => header.indexOf(n);
      for (let i = 1; i < lines.length; i++) {
        const c = splitCsv(lines[i]);
        const mailbox = c[col('User')] ?? null;
        const from = (c[col('From')] ?? '').toLowerCase();
        const subject = c[col('Subject')] ?? null;
        if (isOwnTraffic({ from, subject }, own)) continue;
        // Unattributed is a fact; a wrong attribution sends an analyst after the wrong
        // attack. See src/lib/hunt.ts.
        const hit = attribute(from, subject, searchable);
        const isNew = await record({
          source: 'curated',
          iocValue: hit?.value ?? UNATTRIBUTED,
          kind: hit?.kind ?? 'LURE_STRING',
          surface: 'mailbox',
          subject,
          mailbox,
          detail: hit
            ? `matched ${hit.kind.toLowerCase()} in live mail`
            : 'Gmail matched a lure string in the message body; open the message to see which'
        });
        if (isNew) {
          fresh.push({
            ioc: hit?.value ?? UNATTRIBUTED,
            kind: hit?.kind ?? 'LURE_STRING',
            surface: 'mailbox',
            where: mailbox ?? '?',
            what: subject ?? ''
          });
        }
      }
    }
  }

  // ── 2. payload hosts, curated AND feeds: matched locally ──────────────────
  // Gmail cannot find these. What Warden CAN do is check whether anything staff already
  // reported points at a host now known to be malicious — which is the question that
  // matters when a feed updates hours after a campaign lands.
  const reports = await prisma.wardenReport.findMany({
    where: { reportedAt: { gte: new Date(Date.now() - days * 86_400_000) } },
    select: { id: true, reporter: true, originalSubject: true, payloadHosts: true, payloadUrls: true, state: true }
  });

  const curatedHosts = new Map<string, string>(
    (await prisma.wardenIoc.findMany({ where: { kind: 'PAYLOAD_HOST' }, select: { value: true } }))
      .map((h) => [h.value.toLowerCase(), 'curated'])
  );

  let feedChecked = 0;
  for (const r of reports) {
    const hosts = [
      ...new Set([
        ...(JSON.parse(r.payloadHosts ?? '[]') as string[]),
        ...(JSON.parse(r.payloadUrls ?? '[]') as string[]).map((u) => {
          try { return new URL(u).hostname; } catch { return ''; }
        })
      ].map((h) => h.toLowerCase()).filter(Boolean))
    ];
    for (const host of hosts) {
      let source = curatedHosts.get(host);
      if (!source) {
        const f = await prisma.wardenFeedIoc.findFirst({ where: { host }, select: { source: true, malware: true } });
        feedChecked++;
        if (f) source = f.source;
      }
      if (!source) continue;
      const isNew = await record({
        source, iocValue: host, kind: 'PAYLOAD_HOST', surface: 'report',
        subject: r.originalSubject, mailbox: r.reporter, reportId: r.id,
        detail: `reported message points at a known-malicious host (${source}); report is ${r.state}`
      });
      if (isNew) fresh.push({ ioc: host, kind: 'PAYLOAD_HOST', surface: 'report', where: r.reporter, what: r.originalSubject ?? '' });
    }
  }

  // ── 3. IP indicators against sign-in events ───────────────────────────────
  const ips = await prisma.wardenIoc.findMany({ where: { kind: 'IP' }, select: { value: true } });
  for (const ip of ips) {
    const events = await prisma.wardenLoginEvent.findMany({
      where: { ip: ip.value, ts: { gte: new Date(Date.now() - days * 86_400_000) } },
      select: { mailbox: true, ts: true, eventName: true }
    });
    for (const e of events) {
      const isNew = await record({
        source: 'curated', iocValue: ip.value, kind: 'IP', surface: 'login',
        mailbox: e.mailbox, subject: e.eventName,
        detail: `sign-in from a known-bad address at ${e.ts.toISOString()}`
      });
      if (isNew) fresh.push({ ioc: ip.value, kind: 'IP', surface: 'login', where: e.mailbox, what: e.eventName });
    }
  }

  // Group by indicator. One line per matching message produced 1,981 lines in the first
  // dry run, which is a wall of text, not a report. What an analyst needs first is which
  // indicators are live and how wide each one is spread.
  const byIoc = new Map<string, { kind: string; surface: string; hits: typeof fresh }>();
  for (const f of fresh) {
    const g = byIoc.get(f.ioc) ?? { kind: f.kind, surface: f.surface, hits: [] };
    g.hits.push(f);
    byIoc.set(f.ioc, g);
  }
  const groups = [...byIoc.entries()].sort((a, b) => b[1].hits.length - a[1].hits.length);

  console.log(`\n${fresh.length} new hits across ${groups.length} indicators ` +
    `(${reports.length} reports and ${feedChecked} host lookups checked)`);
  for (const [ioc, g] of groups) {
    const boxes = new Set(g.hits.map((h) => h.where));
    console.log(`\n  ${g.kind}  ${ioc}`);
    console.log(`    ${g.hits.length} message${g.hits.length === 1 ? '' : 's'} in ${boxes.size} mailbox${boxes.size === 1 ? '' : 'es'} (${g.surface})`);
    for (const h of g.hits.slice(0, 4)) {
      console.log(`      ${h.where.padEnd(36)} ${h.what.slice(0, 54)}`);
    }
    if (g.hits.length > 4) console.log(`      ... and ${g.hits.length - 4} more`);
  }
  if (DRY) { console.log('\n--dry: nothing written'); return `${fresh.length} would be recorded`; }

  if (fresh.length) {
    const { text, html } = render({
      title:
        `${groups.length} indicator${groups.length === 1 ? '' : 's'} matched ` +
        `${fresh.length} message${fresh.length === 1 ? '' : 's'}`,
      lede: 'Stored indicators matched live mail, reported messages or sign-in events.',
      blocks: [
        {
          // Grouped, like the console output. One item per matching message made a
          // 1,981-line email, which is a thing nobody opens twice.
          items: groups.slice(0, 20).map(([ioc, g]) => {
            const boxes = new Set(g.hits.map((h) => h.where));
            return {
              title: `${defangUrl(ioc)}  (${g.kind.toLowerCase().replace('_', ' ')})`,
              meta:
                `${g.hits.length} message${g.hits.length === 1 ? '' : 's'} · ` +
                `${boxes.size} mailbox${boxes.size === 1 ? '' : 'es'} · ${g.surface}`,
              detail: g.hits.slice(0, 3).map((h) => `${h.where}: ${h.what.slice(0, 80)}`).join('\n'),
              severity: 'critical' as const
            };
          })
        },
        {
          note:
            'Nothing was deleted. This job is read-only on purpose: a sender-only sweep of a ' +
            'compromised partner-district account would have destroyed 51 live IEP messages, ' +
            'and that account is in the indicator list. Preview before sweeping.'
        }
      ],
      cta: { label: 'Open Warden', href: s.consoleUrl },
      baseUrl: s.consoleUrl
    });
    const subject = `Warden: ${groups.length} indicator${groups.length === 1 ? '' : 's'} matched ${fresh.length} message${fresh.length === 1 ? '' : 's'}`;
    const sent = await sendMail(s.mail, await notifyRecipients(prisma), subject, text, {
      html,
      throttleKey: `hunt-${groups.length}-${groups[0][0]}`
    });
    // Do not swallow this. A hunt that finds something and cannot say so is a silent
    // failure, and the users page already proved how long one of those goes unnoticed.
    // 'throttled' and 'disabled' are operator choices, not faults — say so and move on.
    if (sent.status === 'error') {
      console.error(`notification FAILED: ${sent.error ?? 'unknown error'}`);
    } else if (sent.status !== 'sent') {
      console.log(`notification not sent: ${sent.status}`);
    }
  }

  return `${fresh.length} new hits`;
}

if (process.argv[1]?.includes('hunt-iocs')) {
  run()
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}
