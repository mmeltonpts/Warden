/**
 * Pull public threat-intelligence feeds into WardenFeedIoc.
 *
 *   sudo -u warden npx tsx scripts/sync-feeds.ts
 *
 * WHAT THESE ARE FOR, AND WHAT THEY ARE NOT FOR
 *
 * Feeds are URL- and domain-heavy. Gmail cannot match a domain inside a message body — a
 * scan for a domain provably present in bodies returned ZERO — so turning 100,000 feed URLs
 * into Gmail searches would be 100,000 queries that structurally cannot hit.
 *
 * They are therefore matched LOCALLY, by hunt-iocs.ts, against payload hosts Warden has
 * already extracted from reported messages. That is cheap, and it answers the question that
 * actually matters: "is the thing our staff just reported already known to be malicious?"
 *
 * Kept in their own table, away from WardenIoc. The curated table holds indicators somebody
 * here confirmed by hand; mixing tens of thousands of unverified rows into it would make
 * the IOC page useless.
 *
 * Every fetch is best-effort. A feed being down must never fail the tick.
 */
import { PrismaClient } from '@prisma/client';
import { getSettings } from '../src/lib/settings';

const prisma = new PrismaClient();

interface Row {
  source: string;
  kind: string;
  value: string;
  host: string | null;
  malware?: string | null;
  firstSeen?: Date | null;
}

function hostOf(value: string): string | null {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    // Not a URL — a bare domain or an address is already the host.
    const t = value.trim().toLowerCase();
    return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(t) ? t : null;
  }
}

async function get(url: string, headers: Record<string, string>, timeoutMs = 45_000): Promise<string | null> {
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    const r = await fetch(url, { signal: ac.signal, headers });
    clearTimeout(t);
    if (!r.ok) {
      console.warn(`  ${url} -> HTTP ${r.status}`);
      return null;
    }
    return await r.text();
  } catch (e) {
    console.warn(`  ${url} -> ${(e as Error).message}`);
    return null;
  }
}

/** URLhaus recent CSV. Auth-Key required since abuse.ch tightened access. */
async function urlhaus(key: string): Promise<Row[]> {
  const body = await get('https://urlhaus.abuse.ch/downloads/csv_recent/', key ? { 'Auth-Key': key } : {});
  if (!body) return [];
  const out: Row[] = [];
  for (const line of body.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    // id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    const c = line.split('","').map((x) => x.replace(/^"|"$/g, ''));
    if (c.length < 6) continue;
    const url = c[2];
    if (!/^https?:\/\//i.test(url)) continue;
    const d = new Date(c[1]);
    out.push({
      source: 'urlhaus',
      kind: 'url',
      value: url.slice(0, 500),
      host: hostOf(url),
      malware: c[5] || null,
      firstSeen: Number.isNaN(d.getTime()) ? null : d
    });
  }
  return out;
}

/** ThreatFox IOCs from the last N days. Auth-Key required. */
async function threatfox(key: string, days: number): Promise<Row[]> {
  if (!key) {
    console.warn('  threatfox: skipped, no abuse.ch Auth-Key configured');
    return [];
  }
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 45_000);
    const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      signal: ac.signal,
      headers: { 'Content-Type': 'application/json', 'Auth-Key': key },
      body: JSON.stringify({ query: 'get_iocs', days: Math.min(days, 7) })
    });
    clearTimeout(t);
    if (!r.ok) {
      console.warn(`  threatfox -> HTTP ${r.status}`);
      return [];
    }
    const j = (await r.json()) as { query_status?: string; data?: Array<Record<string, string>> };
    if (j.query_status !== 'ok' || !Array.isArray(j.data)) {
      console.warn(`  threatfox -> ${j.query_status ?? 'unexpected response'}`);
      return [];
    }
    return j.data
      .filter((d) => d.ioc)
      .map((d) => {
        const v = String(d.ioc);
        const type = String(d.ioc_type ?? '');
        const kind = type.includes('url') ? 'url' : type.includes('ip') ? 'ip' : 'domain';
        const d0 = new Date(String(d.first_seen ?? ''));
        return {
          source: 'threatfox',
          kind,
          value: v.slice(0, 500),
          // ip:port is common in this feed; the port is not part of the indicator.
          host: kind === 'ip' ? v.split(':')[0] : hostOf(v),
          malware: d.malware_printable ?? null,
          firstSeen: Number.isNaN(d0.getTime()) ? null : d0
        };
      });
  } catch (e) {
    console.warn(`  threatfox -> ${(e as Error).message}`);
    return [];
  }
}

/** OpenPhish community feed. Plain text, one URL per line, no key. */
async function openphish(): Promise<Row[]> {
  const body = await get('https://openphish.com/feed.txt', {});
  if (!body) return [];
  return body
    .split(/\r?\n/)
    .filter((l) => /^https?:\/\//i.test(l))
    .map((url) => ({
      source: 'openphish',
      kind: 'url',
      value: url.slice(0, 500),
      host: hostOf(url),
      malware: 'phishing',
      firstSeen: null
    }));
}

export async function run() {
  const s = await getSettings(prisma);
  const cfg = s.feeds;
  if (!cfg.enabled) {
    console.log('threat feeds are disabled in Settings');
    return 'disabled';
  }

  const key = cfg.abuseChAuthKey ?? '';
  const batches: Row[] = [];

  if (cfg.urlhaus) { console.log('fetching urlhaus...'); batches.push(...(await urlhaus(key))); }
  if (cfg.threatfox) { console.log('fetching threatfox...'); batches.push(...(await threatfox(key, cfg.retentionDays))); }
  if (cfg.openphish) { console.log('fetching openphish...'); batches.push(...(await openphish())); }

  if (!batches.length) {
    console.log('no rows fetched — check the Auth-Key and that at least one feed is enabled');
    return 'no rows fetched';
  }

  // De-duplicate within the run; the feeds overlap.
  const seen = new Set<string>();
  const rows = batches.filter((r) => {
    const k = r.source + '|' + r.value;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const CHUNK = 1000;
  let stored = 0;
  for (let i = 0; i < rows.length; i += CHUNK) {
    const res = await prisma.wardenFeedIoc.createMany({
      data: rows.slice(i, i + CHUNK).map((r) => ({
        source: r.source,
        kind: r.kind,
        value: r.value,
        host: r.host,
        malware: r.malware ?? null,
        firstSeen: r.firstSeen ?? null
      })),
      skipDuplicates: true
    });
    stored += res.count;
  }

  // Age out. An indicator nobody has seen in a month is noise, not intelligence, and the
  // table is only useful if matching against it stays fast.
  const cutoff = new Date(Date.now() - cfg.retentionDays * 86_400_000);
  const pruned = await prisma.wardenFeedIoc.deleteMany({ where: { fetchedAt: { lt: cutoff } } });

  const total = await prisma.wardenFeedIoc.count();
  const bySource = await prisma.wardenFeedIoc.groupBy({ by: ['source'], _count: { _all: true } });
  console.log(`\n${stored} new, ${pruned.count} pruned, ${total} held`);
  for (const b of bySource.sort((a, b2) => b2._count._all - a._count._all)) {
    console.log(`  ${String(b._count._all).padStart(7)}  ${b.source}`);
  }
  return `${stored} new, ${pruned.count} pruned, ${total} held`;
}

if (process.argv[1]?.includes('sync-feeds')) {
  run()
    .then((r) => console.log(typeof r === 'string' ? '' : r))
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => prisma.$disconnect());
}
