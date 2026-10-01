/**
 * IP ownership lookup via RDAP, with a local cache.
 *
 * WHY: Google tells you a suspicious sign-in happened from `2a09:bac2:7e11:25a5::3c0:59`
 * and nothing else. That address is unreadable, and the judgement an operator has to make
 * — is this a pupil at home or somebody hiding — is entirely a question of who owns it.
 *
 * Looking these up by hand established the point: of 241 suspicious-login alerts, 126 were
 * Comcast, T-Mobile, AT&T, Verizon or Frontier (a pupil on a home or mobile connection),
 * while 57 were Cloudflare WARP and 20 more were OVH, GTHost, Fastly and Datacamp — VPN and
 * hosting. Identical-looking addresses, opposite meanings.
 *
 * RDAP rather than legacy WHOIS: it is a documented JSON API, needs no key, no scraping and
 * no rate-limit negotiation, and it returns the allocation CIDR so one lookup answers for a
 * whole network.
 *
 * Results are cached in WardenNetwork. Allocations change on the order of years, so a cache
 * miss is rare after the first run and the registries are not hammered.
 */
import type { PrismaClient } from '@prisma/client';

export interface NetInfo {
  prefix: string;
  name: string;
  org: string;
  cc: string | null;
  source: string;
}

/**
 * Cache key: /24 for IPv4, /32 for IPv6.
 *
 * Deliberately finer than the typical allocation. Cloudflare WARP occupies both
 * `2a09:bac2::/32` and `2a09:bac3::/32` as separate registrations, and a coarser key would
 * merge two networks under one label.
 */
export function netKey(ip: string): string {
  if (ip.includes(':')) return ip.split(':').slice(0, 2).join(':') + ':';
  return ip.split('.').slice(0, 3).join('.') + '.';
}

/**
 * rdap.org redirects to whichever RIR is authoritative, which avoids hard-coding the
 * region. ARIN and RIPE are tried directly afterwards because the redirector occasionally
 * fails and most of this district's traffic is ARIN anyway.
 */
const ENDPOINTS = [
  'https://rdap.org/ip/',
  'https://rdap.arin.net/registry/ip/',
  'https://rdap.db.ripe.net/ip/'
];

async function fetchRdap(ip: string, timeoutMs: number): Promise<NetInfo | null> {
  for (const base of ENDPOINTS) {
    try {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      const res = await fetch(base + encodeURIComponent(ip), {
        signal: ac.signal,
        headers: { Accept: 'application/rdap+json' },
        redirect: 'follow'
      });
      clearTimeout(timer);
      if (!res.ok) continue;

      const j = (await res.json()) as Record<string, unknown>;
      const entities = (j.entities ?? []) as Array<Record<string, unknown>>;
      const org =
        entities
          .flatMap((e) => {
            const vcard = (e.vcardArray as unknown[] | undefined)?.[1] as unknown[] | undefined;
            return (vcard ?? [])
              .filter((v) => Array.isArray(v) && v[0] === 'fn')
              .map((v) => (v as unknown[])[3] as string);
          })
          .filter(Boolean)[0] ?? '';

      const cidrs = (j.cidr0_cidrs ?? []) as Array<Record<string, unknown>>;
      const prefix = cidrs.length
        ? `${cidrs[0].v4prefix ?? cidrs[0].v6prefix}/${cidrs[0].length}`
        : ((j.handle as string) ?? netKey(ip));

      return {
        prefix: String(prefix),
        name: String(j.name ?? ''),
        org: String(org),
        cc: (j.country as string) ?? null,
        source: new URL(base).hostname
      };
    } catch {
      /* try the next endpoint */
    }
  }
  return null;
}

/**
 * Look an address up, using the cache first.
 *
 * Never throws and never blocks a caller indefinitely: enrichment is a nicety, and a
 * registry being slow must not stall an ingest that is also collecting phishing reports.
 */
export async function lookupIp(
  prisma: PrismaClient,
  ip: string,
  opts: { timeoutMs?: number; maxAgeDays?: number } = {}
): Promise<NetInfo | null> {
  const key = netKey(ip);
  const maxAge = (opts.maxAgeDays ?? 180) * 86_400_000;

  const cached = await prisma.wardenNetwork.findUnique({ where: { netKey: key } }).catch(() => null);
  if (cached && Date.now() - cached.fetchedAt.getTime() < maxAge) {
    return {
      prefix: cached.prefix,
      name: cached.name ?? '',
      org: cached.org ?? '',
      cc: cached.cc,
      source: cached.source ?? 'cache'
    };
  }

  const info = await fetchRdap(ip, opts.timeoutMs ?? 10_000);
  if (!info) return cached
    ? { prefix: cached.prefix, name: cached.name ?? '', org: cached.org ?? '', cc: cached.cc, source: 'stale-cache' }
    : null;

  await prisma.wardenNetwork
    .upsert({
      where: { netKey: key },
      create: {
        netKey: key,
        prefix: info.prefix,
        name: info.name,
        org: info.org,
        cc: info.cc,
        source: info.source,
        sampleIp: ip
      },
      update: { prefix: info.prefix, name: info.name, org: info.org, cc: info.cc, source: info.source, fetchedAt: new Date() }
    })
    .catch(() => undefined);

  return info;
}

export type NetClass = 'residential' | 'anonymizer' | 'unknown';

/**
 * Classify a network from its registered owner rather than from its address.
 *
 * This is what makes the rule portable. A district in Texas gets Spectrum and Frontier
 * named for them without anybody typing a prefix, and the operator only has to say which
 * CATEGORIES matter rather than maintaining a list of allocations.
 *
 * `anonymizer` wins over `residential` on a tie. Cloudflare sells consumer broadband
 * adjacent products and also runs WARP; if a name matches both lists, the cautious reading
 * is the correct one.
 */
export function classifyOrg(
  info: { org?: string | null; name?: string | null },
  residentialPatterns: string[],
  anonymizerPatterns: string[]
): { klass: NetClass; matched: string | null } {
  const hay = `${info.org ?? ''} ${info.name ?? ''}`.toLowerCase();
  for (const p of anonymizerPatterns) {
    const t = p.trim().toLowerCase();
    if (t && hay.includes(t)) return { klass: 'anonymizer', matched: p.trim() };
  }
  for (const p of residentialPatterns) {
    const t = p.trim().toLowerCase();
    if (t && hay.includes(t)) return { klass: 'residential', matched: p.trim() };
  }
  return { klass: 'unknown', matched: null };
}
