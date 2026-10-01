/**
 * Entry point for the 6-hourly sign-in risk scan (warden-loginscan.service).
 *
 * Read-only against Google. Writes only to Warden's own database.
 * Run manually:  sudo -u warden npx tsx scripts/scan-logins.ts
 */
import { PrismaClient } from '@prisma/client';
import { runLoginScan } from '../src/lib/loginscan';
import type { RawLoginEvent, Baseline } from '../src/lib/baseline';
import { ipPrefix } from '../src/lib/baseline';
import type { NetVerdict } from '../src/lib/baseline';
import { lookupIp, classifyOrg, netKey } from '../src/lib/rdap';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { sendMail, riskDigest, scanFailure } from '../src/lib/mailer';

const prisma = new PrismaClient();

export async function run(opts: { days?: number } = {}) {
  void opts;
  const settings = await getSettings(prisma);
  // Students are only scanned when the operator asks. ~6,336 more mailboxes is a lot of
  // new flags on a queue somebody has to read, and the events are free either way — the
  // GAM report is tenant-wide, so this only decides what is kept.
  const scanDomains = [settings.domains.staff];
  if (settings.scanStudentSignIns && settings.domains.students) {
    scanDomains.push(settings.domains.students);
  }

  const raised: Array<{ mailbox: string; ts: Date; score: number; reasons: string[]; ip?: string | null; geo?: string | null }> = [];

  // ── network classification ──────────────────────────────────────────────────
  // The datacenter-ASN list cannot separate Cloudflare WARP on a student's phone from
  // Cloudflare proxying an attack — both are AS13335. RDAP names the registered owner of
  // the netblock, which is the evidence that settles it.
  //
  // Two layers of caching, because this runs once per scored event: lookupIp persists to
  // WardenNetwork keyed by /24, and this memo keeps one scan from asking the database the
  // same question hundreds of times. A district shares very few networks.
  const residentialOrgs = (settings.alerts.residentialOrgs ?? '').split(',').filter(Boolean);
  const anonymizerOrgs = (settings.alerts.anonymizerOrgs ?? '').split(',').filter(Boolean);
  const netMemo = new Map<string, { klass: NetVerdict['klass']; org: string | null } | null>();

  const districtPrefix = (settings.districtIpPrefix ?? '').trim();

  async function classifyIp(ip: string | null | undefined): Promise<NetVerdict | null> {
    if (!ip) return null;

    // On-network is decided before RDAP and regardless of it: the district's own egress
    // range is a fact we hold locally, and it should not depend on a lookup that may be
    // slow, cached stale, or down.
    const onDistrictNetwork = districtPrefix.length > 0 && ip.startsWith(districtPrefix);

    let key: string;
    try {
      key = netKey(ip);
    } catch {
      // Unparseable address. On-network is still knowable, and the ASN fallback applies.
      return onDistrictNetwork ? { klass: 'unknown', onDistrictNetwork } : null;
    }

    // The memo holds ONLY the RDAP-derived part, because its key is the /24 while
    // onDistrictNetwork is a property of the individual address. A district prefix
    // narrower than a /24 would otherwise get one address's answer served to another's.
    let owner = netMemo.get(key);
    if (owner === undefined) {
      const info = await lookupIp(prisma, ip, { timeoutMs: 10_000 }).catch(() => null);
      owner = info
        ? {
            klass: classifyOrg(info, residentialOrgs, anonymizerOrgs).klass,
            org: info.org || info.name || null
          }
        : null;
      netMemo.set(key, owner);
    }

    return { klass: owner?.klass ?? 'unknown', org: owner?.org ?? null, onDistrictNetwork };
  }

  const run = await prisma.wardenScanRun.create({
    data: { windowStart: new Date(), windowEnd: new Date() }
  });

  try {
    const result = await runLoginScan(
      {
        gamPath: settings.gamPath,
        classifyIp,
        flagThreshold: settings.riskFlagThreshold,
        lookbackHours: settings.scanLookbackHours,
        baselineWindowDays: settings.baselineWindowDays,
        homeCountries: (settings.homeCountries || 'US').split(',').map((c) => c.trim().toUpperCase()).filter(Boolean),

        async upsertEvents(events: RawLoginEvent[]) {
          if (!events.length) return 0;
          const res = await prisma.wardenLoginEvent.createMany({
            data: events.map((e) => ({
              mailbox: e.mailbox,
              ts: e.ts,
              eventName: e.eventName,
              ip: e.ip ?? null,
              ipPrefix: ipPrefix(e.ip) ?? null,
              asn: e.asn ?? null,
              geo: e.geo ?? null,
              challenge: e.challenge ?? null,
              suspicious: !!e.suspicious,
              sensitive: e.sensitive ?? null
            })),
            skipDuplicates: true
          });
          return res.count;
        },

        async historyFor(mailbox: string, since: Date) {
          const rows = await prisma.wardenLoginEvent.findMany({
            where: { mailbox, ts: { gte: since } },
            orderBy: { ts: 'asc' }
          });
          return rows.map((r) => ({
            mailbox: r.mailbox,
            ts: r.ts,
            eventName: r.eventName,
            ip: r.ip,
            asn: r.asn,
            geo: r.geo,
            challenge: r.challenge,
            suspicious: r.suspicious,
            sensitive: r.sensitive
          }));
        },

        async loadBaseline(mailbox: string) {
          const b = await prisma.wardenBaseline.findUnique({ where: { mailbox } });
          if (!b) return null;
          return {
            mailbox: b.mailbox,
            knownPrefixes: JSON.parse(b.knownPrefixes),
            knownAsns: JSON.parse(b.knownAsns),
            knownGeos: JSON.parse(b.knownGeos),
            knownChallenges: JSON.parse(b.knownChallenges),
            usesPasskey: b.usesPasskey,
            typicalHours: JSON.parse(b.typicalHours),
            eventCount: b.eventCount,
            mature: b.mature
          } satisfies Baseline;
        },

        async saveBaseline(b: Baseline, firstSeen?: Date, lastSeen?: Date) {
          const data = {
            knownPrefixes: JSON.stringify(b.knownPrefixes),
            knownAsns: JSON.stringify(b.knownAsns),
            knownGeos: JSON.stringify(b.knownGeos),
            knownChallenges: JSON.stringify(b.knownChallenges),
            usesPasskey: b.usesPasskey,
            typicalHours: JSON.stringify(b.typicalHours),
            eventCount: b.eventCount,
            mature: b.mature,
            rebuiltAt: new Date(),
            firstSeen: firstSeen ?? null,
            lastSeen: lastSeen ?? null
          };
          await prisma.wardenBaseline.upsert({
            where: { mailbox: b.mailbox },
            create: { mailbox: b.mailbox, ...data },
            update: data
          });
        },

        async raiseFlag(f) {
          try {
            raised.push(f);
            await prisma.wardenRiskFlag.create({
              data: {
                mailbox: f.mailbox,
                ts: f.ts,
                score: f.score,
                reasons: JSON.stringify(f.reasons),
                ip: f.ip ?? null,
                asn: f.asn ?? null,
                geo: f.geo ?? null,
                challenge: f.challenge ?? null,
                suspicious: f.suspicious
              }
            });
            return true;
          } catch {
            return false; // unique(mailbox, ts) — already flagged by an earlier overlapping scan
          }
        }
      },
      scanDomains
    );

    await prisma.wardenScanRun.update({
      where: { id: run.id },
      data: {
        finishedAt: new Date(),
        windowStart: result.windowStart,
        windowEnd: result.windowEnd,
        eventsSeen: result.eventsSeen,
        eventsNew: result.eventsNew,
        flagsRaised: result.flagsRaised,
        baselines: result.baselinesRebuilt,
        ok: true
      }
    });

    // Notify AFTER the run is recorded, so a relay outage cannot fail the scan.
    if (raised.length) {
      const rcpt = await notifyRecipients(prisma);
      const msg = riskDigest(
        raised.sort((a, b) => b.score - a.score),
        settings.consoleUrl
      );
      const r = await sendMail(settings.mail, rcpt, msg.subject, msg.text, {
        throttleKey: `risk-${new Date().toISOString().slice(0, 13)}`
      });
      if (r.status !== 'sent' && r.status !== 'disabled' && r.status !== 'throttled') {
        console.error(`notification failed: ${r.status} ${r.error ?? ''}`);
      }
    }

    console.log(
      `scan ok: ${result.eventsSeen} events (${result.eventsNew} new), ` +
        `${result.baselinesRebuilt} baselines, ${result.flagsRaised} flags raised ` +
        `(baseline window ${settings.baselineWindowDays}d, lookback ${settings.scanLookbackHours}h)`
    );
  } catch (err) {
    await prisma.wardenScanRun.update({
      where: { id: run.id },
      data: { finishedAt: new Date(), ok: false, error: String(err).slice(0, 1000) }
    });
    console.error('scan failed:', err);
    try {
      const s = await getSettings(prisma);
      const msg = scanFailure(String(err).slice(0, 400), 'the Warden console');
      await sendMail(s.mail, await notifyRecipients(prisma), msg.subject, msg.text, {
        throttleKey: 'scan-failure'
      });
    } catch {
      /* notification is best-effort; the scan failure is already recorded */
    }
    process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
}

// CLI entry point only. Importing this module (tick.ts does) must not run anything.
if (process.argv[1]?.includes('scan-logins')) void run();