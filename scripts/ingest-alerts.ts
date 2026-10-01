/**
 * Ingest Google Workspace Alert Center alerts.
 *
 *   sudo -u warden npx tsx scripts/ingest-alerts.ts [--days N]
 *
 * WHY THIS EXISTS, and why it is not the same as scripts/ingest-reports.ts:
 *
 * There are two independent ways a member of staff can report a phish, and they share no
 * plumbing at all.
 *
 *   1. The KnowBe4 Phish Alert Button forwards the message to a mailbox. ingest-reports.ts
 *      reads that mailbox.
 *   2. Gmail's OWN "Report phishing" menu item forwards nothing, to nobody. Google raises
 *      an Alert Center alert and that is the entire record.
 *
 * 101 user-reported phishing alerts had accumulated before Warden could read channel 2.
 *
 * Pulled through the API rather than from the alert EMAIL on purpose. The email is
 * observed to arrive up to 24 hours late, and carries far less: the API returns message
 * ids, recipients, subjects, body snippets and attachment hashes immediately.
 *
 * `rfcMessageId` is an RFC822 Message-ID, NOT a Gmail API id, so it cannot be handed to
 * `show messages ids`. It is searchable as `rfc822msgid:<id>`, which turns one person's
 * report into a domain-wide scope in a single query.
 *
 * Read-only against Google.
 */
import { PrismaClient } from '@prisma/client';
import { spawn } from 'node:child_process';
import { getSettings } from '../src/lib/settings';
import { splitCsv } from '../src/lib/worker';
import { extractPayloadHosts, extractPayloadUrls, dedupeKey } from '../src/lib/reports';
import { lookupIp, classifyOrg } from '../src/lib/rdap';

const prisma = new PrismaClient();

/** Alert types that also belong in the human triage queue as reports. */
const REPORT_TYPES = ['User reported phishing', 'User reported spam spike'];

/** Marks a report body that already contains the real fetched message, so re-runs skip it. */
const BODY_MARKER = '----- the reported message as retrieved from the mailbox -----';

/**
 * Parse the `prefix=Label` benign-network setting.
 *
 * Matching is a plain string prefix on the address, which is crude but honest: these are
 * allocation boundaries taken from RDAP, not arbitrary guesses, and a prefix test cannot
 * accidentally widen the way a hand-written CIDR calculation can.
 */
function parseNetworks(spec: string): Array<{ prefix: string; label: string }> {
  return spec
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const i = s.indexOf('=');
      return i < 0
        ? { prefix: s, label: s }
        : { prefix: s.slice(0, i).trim(), label: s.slice(i + 1).trim() };
    })
    .filter((x) => x.prefix);
}

function argDays(): number | null {
  const i = process.argv.indexOf('--days');
  if (i < 0) return null;
  const n = Number(process.argv[i + 1]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

/** stderr inherited, never left as an unread pipe — see CLAUDE.md. */
function gam(gamPath: string, args: string[], timeoutMs = 900_000): Promise<string> {
  return new Promise((resolve) => {
    let out = '';
    const c = spawn(gamPath, args, { stdio: ['ignore', 'pipe', 'inherit'] });
    const t = setTimeout(() => c.kill('SIGKILL'), timeoutMs);
    c.stdout.on('data', (d) => (out += d));
    c.on('error', () => resolve(out));
    c.on('close', () => {
      clearTimeout(t);
      resolve(out);
    });
  });
}

function asDate(v: string | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export async function run(opts: { days?: number } = {}) {
  void opts;
  const s = await getSettings(prisma);
  const cfg = s.alerts;
  if (!cfg.enabled) {
    console.log('Alert Center ingestion is disabled in Settings.');
    return { stored: 0, suppressed: 0, asReports: 0, merged: 0, fetched: 0, newIds: [] as string[] };
  }

  const days = argDays() ?? cfg.lookbackDays;
  const since = new Date(Date.now() - days * 86_400_000).toISOString().replace(/\.\d+Z$/, 'Z');
  const wanted = (cfg.types ?? '').split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  const excluded = (cfg.excludeTypes ?? '').split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);

  console.log(`fetching alerts created since ${since}`);
  const csv = await gam(s.gamPath, ['print', 'alerts', 'filter', `createTime >= "${since}"`]);

  const lines = csv.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) {
    console.log('no alerts returned');
    return { stored: 0, suppressed: 0, asReports: 0, merged: 0, fetched: 0, newIds: [] as string[] };
  }
  const header = splitCsv(lines[0]);
  const idx = new Map(header.map((h, i) => [h, i]));
  const get = (c: string[], k: string) => {
    const i = idx.get(k);
    return i === undefined ? undefined : (c[i] || undefined);
  };

  let seen = 0;
  let written = 0;
  let asReports = 0;
  let suppressed = 0;
  let fetched = 0;
  let merged = 0;
  let rdapHits = 0;
  const newIds: string[] = [];
  let anonymizers = 0;
  let foreignHits = 0;
  const homeCountries = (s.homeCountries || 'US').split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
  const residentialOrgs = (cfg.residentialOrgs ?? '').split(',').filter(Boolean);
  const anonymizerOrgs = (cfg.anonymizerOrgs ?? '').split(',').filter(Boolean);
  const networks = parseNetworks(cfg.benignNetworks ?? '');
  const byType = new Map<string, number>();
  const skippedTypes = new Map<string, number>();

  for (let i = 1; i < lines.length; i++) {
    const c = splitCsv(lines[i]);
    const alertId = get(c, 'alertId');
    const type = get(c, 'type');
    if (!alertId || !type) continue;
    seen++;

    // EXCLUDE first, then an optional allow-list. Defaulting to 'store everything except
    // what is named' means a new alert type — a custom activity rule added next week —
    // lands in the queue instead of being silently skipped. An include list fails by going
    // quiet, which is the failure this whole tool exists to prevent.
    const lower = type.toLowerCase();
    if (excluded.includes(lower) || (wanted.length && !wanted.includes(lower))) {
      skippedTypes.set(type, (skippedTypes.get(type) ?? 0) + 1);
      continue;
    }

    const shaCount = Number(get(c, 'data.messages.0.attachmentsSha256Hash') ?? 0);
    const shas: string[] = [];
    for (let n = 0; n < (Number.isFinite(shaCount) ? shaCount : 0); n++) {
      const v = get(c, `data.messages.0.attachmentsSha256Hash.${n}`);
      if (v) shas.push(v);
    }

    const data = {
      type,
      source: get(c, 'source') ?? null,
      severity: get(c, 'metadata.severity') ?? null,
      googleState: get(c, 'metadata.status') ?? null,
      createTime: asDate(get(c, 'createTime')) ?? new Date(),
      startTime: asDate(get(c, 'startTime')),
      endTime: asDate(get(c, 'endTime')),
      email: get(c, 'data.email')?.toLowerCase() ?? null,
      fromHeader: get(c, 'data.maliciousEntity.fromHeader')?.toLowerCase() ?? null,
      ip: get(c, 'data.loginDetails.ipAddress') ?? null,
      subject: get(c, 'data.messages.0.subjectText') ?? null,
      recipient: get(c, 'data.messages.0.recipient')?.toLowerCase() ?? null,
      rfcMessageId: get(c, 'data.messages.0.messageId') ?? null,
      bodySnippet: get(c, 'data.messages.0.messageBodySnippet')?.slice(0, 2000) ?? null,
      attachmentSha: JSON.stringify(shas),
      messageCount: Number(get(c, 'data.messages') ?? 0) || 0,
      investigateLink: get(c, 'securityInvestigationToolLink') ?? null
    };

    // A suspicious login from a residential or mobile-carrier range is a pupil at home,
    // not an intrusion. 239 of 241 of these alerts were students, and Google raises one
    // whenever a device appears on a new consumer IPv6 delegation — which Comcast and
    // T-Mobile rotate constantly. Left unfiled they bury the handful that matter.
    //
    // VPN, proxy and hosting ranges are deliberately NOT in the list and stay NEW.
    const existingAlert = await prisma.wardenAlert.findUnique({ where: { alertId } });
    let autoState: string | null = null;
    let autoNote: string | null = null;
    let net: { org?: string; prefix?: string; klass?: string; cc?: string | null } = {};

    if (data.ip) {
      // Who owns this address? Answering that is the whole judgement, and it is the one
      // thing Google does not tell us.
      if (cfg.rdapEnabled) {
        const info = await lookupIp(prisma, data.ip, { timeoutMs: 10_000 });
        if (info) {
          const c = classifyOrg(info, residentialOrgs, anonymizerOrgs);
          net = { org: info.org || info.name, prefix: info.prefix, klass: c.klass, cc: info.cc };
          if (c.klass !== 'unknown') rdapHits++;
          const foreign = !!info.cc && !homeCountries.includes(info.cc.toUpperCase());
          if (type === 'Suspicious login' && !existingAlert?.reviewedBy) {
            if (foreign) {
              // Never auto-filed, whatever kind of network. "Residential" answers "is this a
              // home connection" — it says nothing about WHOSE home, or which continent.
              autoNote =
                `OUTSIDE ${homeCountries.join('/')}: ${net.org} (${info.prefix}) is registered in ${info.cc}. ` +
                'Never auto-filed. Confirm with the user before closing.';
              foreignHits++;
            } else if (c.klass === 'residential') {
              autoState = 'BENIGN';
              autoNote = `Auto-filed: sign-in from ${net.org} (${info.prefix}). A residential or carrier network is not travel.`;
              suppressed++;
            } else if (c.klass === 'anonymizer') {
              // Explicitly NOT suppressed. Named so an operator knows why it is still here.
              autoNote = `${net.org} (${info.prefix}) is a VPN, proxy or hosting network — deliberately left for review rather than auto-filed.`;
              anonymizers++;
            }
          }
        }
      }

      // The hand-maintained prefix list still runs, as a fallback for anything RDAP could
      // not resolve and for local networks no registry describes usefully.
      const netForeign = !!net.cc && !homeCountries.includes(net.cc.toUpperCase());
      if (!autoState && !netForeign && type === 'Suspicious login' && !existingAlert?.reviewedBy && net.klass !== 'anonymizer') {
        const hit = networks.find((n) => data.ip!.startsWith(n.prefix));
        if (hit) {
          autoState = 'BENIGN';
          autoNote = `Auto-filed: sign-in from ${hit.label} (${hit.prefix}). A residential or carrier network is not travel.`;
          suppressed++;
        }
      }
    }

    // Upsert on alertId. Google updates alerts in place (status changes), so re-running
    // must refresh rather than duplicate — and must not clobber Warden's own triage state.
    await prisma.wardenAlert.upsert({
      where: { alertId },
      create: { alertId, ...data, ipOrg: net.org ?? null, ipNet: net.prefix ?? null, ipClass: net.klass ?? null, ipCountry: net.cc ?? null, ...(autoState ? { state: autoState as never, notes: autoNote } : {}) },
      update: { ...data, ipOrg: net.org ?? null, ipNet: net.prefix ?? null, ipClass: net.klass ?? null, ipCountry: net.cc ?? null,
        // A foreign sign-in that an earlier ingest auto-filed as benign — before this code
        // looked at country — goes back to NEW. Never touches anything a human decided.
        ...(net.cc && !homeCountries.includes(net.cc.toUpperCase()) && existingAlert?.state === 'BENIGN' && !existingAlert?.reviewedBy ? { state: 'NEW' as never } : {}), ...(autoNote && !existingAlert?.reviewedBy ? { notes: autoNote } : {}), ...(autoState && !existingAlert?.reviewedBy ? { state: autoState as never } : {}) }
    });
    written++;
    if (!existingAlert) newIds.push(alertId);
    byType.set(type, (byType.get(type) ?? 0) + 1);

    // A user-reported phish is a report. It belongs in the same queue as the PAB reports
    // so nobody has to remember there are two places to look — that split is exactly how
    // 504 reports went unread for six months.
    if (REPORT_TYPES.includes(type) && data.recipient) {
      const msgId = `alert:${alertId}`;
      const existingReport = await prisma.wardenReport.findUnique({ where: { msgId } });

      // Google's snippet is about 100 characters and rarely enough to judge anything.
      // But the alert carries an RFC822 Message-ID, and the reporter still has the message
      // — so look it up in their own mailbox and store the real thing, with the payload
      // links extracted exactly as a Phish Alert Button report gets.
      //
      // `in:anywhere` matters: a reported phish is usually already in Spam or Trash.
      let realBody = '';
      let hosts: string[] = [];
      let urls: string[] = [];
      const alreadyFetched = existingReport?.bodyText?.includes(BODY_MARKER) ?? false;
      if (cfg.fetchBodies && data.rfcMessageId && !alreadyFetched) {
        realBody = await gam(
          s.gamPath,
          ['user', data.recipient, 'show', 'messages',
           'query', `rfc822msgid:${data.rfcMessageId} in:anywhere`, 'showbody'],
          120_000
        );
        if (realBody.trim()) {
          const own = [s.domains.staff, s.domains.students].filter(Boolean);
          hosts = extractPayloadHosts(realBody, own);
          urls = extractPayloadUrls(realBody, own);
          fetched++;
        }
      }

      const header =
        `[Google Workspace Alert Center — ${type}]\n` +
        `Severity: ${data.severity ?? 'unknown'}\n` +
        `Reported by: ${data.recipient}\n` +
        `Sender: ${data.fromHeader ?? 'unknown'}\n` +
        `Subject: ${data.subject ?? 'unknown'}\n` +
        `Messages in alert: ${data.messageCount}\n` +
        (shas.length ? `Attachment SHA-256:\n  ${shas.join('\n  ')}\n` : '') +
        (data.rfcMessageId
          ? `\nScope this across the domain with:\n  rfc822msgid:${data.rfcMessageId}\n`
          : '') +
        `\nGoogle snippet:\n${data.bodySnippet ?? '(none)'}\n`;

      const reportData = {
        reporter: data.recipient,
        reportedAt: data.createTime,
        reportedTo: 'google-alert-center',
        source: 'GOOGLE_ALERT',
        originalSender: data.fromHeader,
        originalSubject: data.subject,
        originalTo: data.recipient,
        payloadHosts: JSON.stringify(hosts),
        payloadUrls: JSON.stringify(urls),
        bodyText: realBody.trim()
          ? `${header}\n${BODY_MARKER}\n${realBody.slice(0, 64_000)}`
          : `${header}\n(The message itself could not be retrieved from the reporter's mailbox — ` +
            `it may have been deleted, or body fetching is off in Settings.)\n`
      };

      // Did this same person already report this same message through the Phish Alert
      // Button? Then this is ONE event seen by two channels, not two things to triage.
      // Link the alert to the existing report and leave the queue length honest.
      const key = dedupeKey(data.recipient, data.fromHeader, data.subject);
      const twin = await prisma.wardenReport.findFirst({
        where: { dedupeKey: key, msgId: { not: msgId } }
      });

      if (twin) {
        await prisma.wardenReport.update({
          where: { id: twin.id },
          data: {
            alertId,
            // The alert carries things the forwarded copy does not — attachment hashes and
            // an rfc822msgid that scopes the whole domain. Keep the richer body.
            ...(realBody.trim() && !twin.bodyText?.includes(BODY_MARKER)
              ? { bodyText: reportData.bodyText, payloadHosts: reportData.payloadHosts, payloadUrls: reportData.payloadUrls }
              : {})
          }
        });
        // The report is the single place this gets judged, so mirror its verdict here.
        await prisma.wardenAlert.update({
          where: { alertId },
          data: { state: twin.state as never, notes: `Same event as an existing report from ${data.recipient}. Triaged in Reports.` }
        });
        merged++;
      } else {
        await prisma.wardenReport.upsert({
          where: { msgId },
          // Never overwrite an existing triage decision; only refresh the extracted content.
          create: { msgId, ...reportData, alertId, dedupeKey: key, state: 'NEW' },
          update: { ...reportData, alertId, dedupeKey: key }
        });
        // Keep the alert row in step with whatever the report now says.
        const rep = await prisma.wardenReport.findUnique({ where: { msgId }, select: { state: true } });
        if (rep && rep.state !== 'NEW') {
          await prisma.wardenAlert.update({ where: { alertId }, data: { state: rep.state as never } });
        }
        asReports++;
      }
    }
  }

  console.log(`\n${seen} alerts returned, ${written} stored, ${asReports} also filed as reports`);
  if (byType.size) {
    console.log('\nstored by type:');
    for (const [t, n] of [...byType.entries()].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${String(n).padStart(5)}  ${t}`);
    }
  }
  if (skippedTypes.size) {
    console.log('\nskipped (not in alerts.types):');
    for (const [t, n] of [...skippedTypes.entries()].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${String(n).padStart(5)}  ${t}`);
    }
  }

  return { stored: written, suppressed, asReports, merged, fetched, newIds };
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('ingest-alerts')) {
  run()
    .then((r) => { if (r && typeof r !== 'string') console.log(JSON.stringify(r)); })
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}