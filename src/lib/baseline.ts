/**
 * Per-mailbox sign-in baselining and risk scoring.
 *
 * Why learned normals rather than static rules
 * --------------------------------------------
 * Consumer ISP and carrier egress geolocates to the nearest metro hub, often in the next
 * state, so "out of state" flags several hundred staff a week. AT&T Mobility IPv6
 * geolocates to Texas wherever the handset actually is — that artefact alone produced
 * a false "second compromise" during the September incidents until it was checked
 * against the user's own history.
 *
 * What actually separated the two real takeovers (2026-09-13 and 2026-09-22) from 265
 * benign off-network prompts was not any single field. It was the combination:
 *
 *      a network this mailbox has never used
 *    + an MFA challenge that was issued AND passed
 *    + Google's own is_suspicious flag
 *    + in one case, a location change too fast to be physical
 *
 * Passkeys invert the picture. Two staff were flagged suspicious by Google in the same
 * window; both authenticated with passkeys, which
 * cannot be relayed, so there was nothing to steal. A passkey login is evidence of
 * safety, not risk, and is scored accordingly.
 */
import type { NetClass } from './rdap';

export interface RawLoginEvent {
  mailbox: string;
  ts: Date;
  eventName: string;
  ip?: string | null;
  asn?: string | null;
  geo?: string | null;
  challenge?: string | null;
  suspicious?: boolean;
  sensitive?: string | null;
}

export interface Baseline {
  mailbox: string;
  knownPrefixes: string[];
  knownAsns: string[];
  knownGeos: string[];
  knownChallenges: string[];
  usesPasskey: boolean;
  typicalHours: number[];
  eventCount: number;
  mature: boolean;
}

/**
 * Learn on the network block, not the address. Residential v4 rotates within a /24;
 * consumer IPv6 rotates the low bits every reconnect, so anything narrower than a /48
 * treats one home as a new location daily.
 */
export function ipPrefix(ip: string | null | undefined): string | null {
  if (!ip) return null;
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return parts.slice(0, 3).join(':') + '::/48';
  }
  const octets = ip.split('.');
  if (octets.length !== 4) return null;
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
}

/** Hosting / VPN / datacenter ASNs. An interactive staff login should not come from one. */
const DATACENTER_ASNS = new Set([
  '174', //    Cogent — attacker source, first confirmed takeover
  '40317', //  attacker source, second confirmed takeover
  '16509', //  AWS
  '14618', //  AWS
  '15169', //  Google Cloud
  '8075', //   Azure
  // Cloudflare. WARP is consumer and ordinary here; the same ASN also proxies attacks.
  // This entry is therefore only decisive when RDAP cannot classify the netblock — see
  // the infrastructure section of assessRisk.
  '13335',
  '20473', //  Vultr
  '14061', //  DigitalOcean
  '16276', //  OVH
  '24940', //  Hetzner
  '63023', //  GTHost
  '9009', //   M247
  '212238' //  Datacamp
]);

/** Challenge methods that can be relayed in real time by an adversary-in-the-middle. */
const RELAYABLE = /(idv_preregistered_phone|device_prompt|idv_|sms|prompt)/i;
/** Challenge methods that cannot. */
const PHISHING_RESISTANT = /(passkey|security_key|fido|webauthn)/i;

export function buildBaseline(mailbox: string, events: RawLoginEvent[]): Baseline {
  const prefixCount = new Map<string, number>();
  const asns = new Set<string>();
  const geos = new Set<string>();
  const challenges = new Set<string>();
  const hours = new Set<number>();
  let usesPasskey = false;

  for (const e of events) {
    const p = ipPrefix(e.ip);
    if (p) prefixCount.set(p, (prefixCount.get(p) ?? 0) + 1);
    if (e.asn) asns.add(e.asn);
    if (e.geo) geos.add(e.geo);
    if (e.challenge && e.challenge !== 'none') challenges.add(e.challenge);
    if (e.challenge && PHISHING_RESISTANT.test(e.challenge)) usesPasskey = true;
    hours.add(e.ts.getUTCHours());
  }

  // A prefix seen once is not yet "normal" — that is exactly what a first intrusion
  // looks like. Require two sightings before it counts as known.
  const knownPrefixes = [...prefixCount.entries()].filter(([, n]) => n >= 2).map(([p]) => p);

  return {
    mailbox,
    knownPrefixes,
    knownAsns: [...asns],
    knownGeos: [...geos],
    knownChallenges: [...challenges],
    usesPasskey,
    typicalHours: [...hours].sort((a, b) => a - b),
    eventCount: events.length,
    // Below ~20 events the baseline over-flags; scores stay advisory until then.
    mature: events.length >= 20
  };
}

export interface RiskAssessment {
  score: number;
  reasons: string[];
  flag: boolean;
}

/**
 * What RDAP says about the netblock an event came from.
 *
 * Type-only import: rdap.ts talks to Prisma and the network, and baseline.ts is a pure
 * scoring module with unit tests. The type is erased at compile time, so importing it
 * costs nothing at runtime and the two definitions cannot drift apart.
 */
export interface NetVerdict {
  klass: NetClass;
  /** Registered owner, for the reason text — "Cloudflare WARP", "Comcast Cable". */
  org?: string | null;
  /**
   * The address is inside the district's own egress range (Settings → Sign-in risk,
   * `districtIpPrefix`). Somebody physically on site, behind the district firewall.
   */
  onDistrictNetwork?: boolean;
  /**
   * ISO 3166 alpha-2 country of the netblock from RDAP. Used as the fallback for the "foreign"
   * signal when Google's own location string omits the country (it often omits the subdivision,
   * and sometimes the whole thing), so a genuinely foreign sign-in Google did not geo-tag is
   * still caught.
   */
  cc?: string | null;
}

export const FLAG_THRESHOLD = 50;

/**
 * Score one event against a mailbox's learned normal.
 *
 * `recent` is that mailbox's other events in the same scan window, used only for the
 * impossible-travel check.
 */
export function assessRisk(
  event: RawLoginEvent,
  baseline: Baseline | null,
  recent: RawLoginEvent[] = [],
  net?: NetVerdict | null,
  /**
   * Operator-tunable, from Settings → Sign-in risk. Defaults to FLAG_THRESHOLD.
   *
   * This was a settings field that nothing read for weeks: an admin could change it
   * mid-incident, see "Saved", and get exactly the same flags. A control that lies about
   * having an effect is worse than no control.
   */
  threshold: number = FLAG_THRESHOLD,
  /** Settings → Sign-in risk → Home countries. ISO 3166 alpha-2, upper case. */
  homeCountries: string[] = ['US']
): RiskAssessment {
  const reasons: string[] = [];
  let score = 0;

  // Only successful authentications matter for takeover. A failed challenge is noise.
  if (event.eventName !== 'login_success') return { score: 0, reasons: [], flag: false };

  const prefix = ipPrefix(event.ip);
  const challenge = event.challenge ?? '';
  const relayable = RELAYABLE.test(challenge);
  const resistant = PHISHING_RESISTANT.test(challenge);

  // ── Google's own verdict ────────────────────────────────────────────────────
  if (event.suspicious) {
    score += 40;
    reasons.push('Google flagged this sign-in as suspicious');
  }

  /**
   * A consumer VPN presents a new network, a new ASN and a new region AT THE SAME TIME,
   * because that is the product. Scoring those as three independent signals counts one
   * fact three times and reliably lands on 50 — which is how roughly 90 Cloudflare WARP
   * sign-ins became flags in a single backfill without any of them being suspicious.
   *
   * So when RDAP identifies the netblock as a privacy relay, the novelty of the exit node
   * is expected and is scored once, lightly. Everything that is NOT explained by the VPN —
   * Google calling it suspicious, a relayable MFA challenge being passed, a filter being
   * created — still scores in full, which is what keeps a VPN from being a hiding place.
   */
  const vpn = net?.klass === 'anonymizer';

  /**
   * Outside the home countries: flagged on its own.
   *
   * Google's location for a sign-in is "US-IN", "NG-LA" — country, then subdivision. The
   * scorer used to treat the whole string as one opaque "region", so a sign-in from Lagos
   * scored the same +15 "new region" as one from the next state over. For a district whose staff are
   * almost all in one county, a foreign sign-in is the single cheapest signal a human
   * should look at every time.
   *
   * Scored at the flag threshold by itself, and deliberately NOT suppressed by the
   * district-network or VPN rules below: a VPN exiting abroad is still worth a phone call,
   * and the reason text says it was a VPN so the call is a quick one.
   */
  const geoCountry = event.geo?.split('-')[0]?.toUpperCase() || null;
  const rdapCc = net?.cc ? net.cc.toUpperCase() : null;
  // Prefer Google's own location; fall back to the RDAP country of the IP when Google omits it,
  // so a foreign sign-in Google did not geo-tag is not silently missed.
  const usedRdap = !(geoCountry && geoCountry.length === 2) && !!(rdapCc && rdapCc.length === 2);
  const country = (geoCountry && geoCountry.length === 2) ? geoCountry : (usedRdap ? rdapCc : null);
  const foreign = !!country && !homeCountries.includes(country);
  if (foreign) {
    score += 50;
    const where = usedRdap ? `IP registered in ${country}` : (event.geo ?? country);
    reasons.push(
      `Sign-in located OUTSIDE ${homeCountries.join('/')} (${where})` +
        (vpn ? ' — through a VPN, so possibly the exit node rather than the person' : '')
    );
  }

  /**
   * Sign-in from the district's own egress range. Somebody sat in a building, behind the
   * firewall, on equipment the district controls — the strongest ordinary evidence of
   * legitimacy this data contains, and it scores like the passkey rule: it lowers risk,
   * it never raises it.
   *
   * Not a free pass. Google calling the sign-in suspicious, and a sensitive Gmail action,
   * both still score in full: an attacker with a foothold on a district machine, or a
   * malicious insider, is exactly the case where "it came from inside" is the wrong
   * conclusion. What this suppresses is the novelty trio, because a new subnet inside the
   * district's own range is a new VLAN or a new building, not an intrusion.
   */
  const onNetwork = net?.onDistrictNetwork === true;
  if (onNetwork) {
    score -= 25;
    reasons.push('Sign-in from the district network — on site, behind the firewall');
  }

  // ── novelty against the learned normal ──────────────────────────────────────
  if (baseline) {
    if (prefix && !baseline.knownPrefixes.includes(prefix) && !onNetwork) {
      score += vpn ? 5 : 20;
      reasons.push(
        vpn
          ? `New network (${prefix}) — expected, this is a VPN exit node`
          : `New network for this user (${prefix})`
      );
    }
    if (!vpn && !onNetwork && event.asn && !baseline.knownAsns.includes(event.asn)) {
      score += 15;
      reasons.push(`New ASN for this user (AS${event.asn})`);
    }
    if (!vpn && !onNetwork && event.geo && !baseline.knownGeos.includes(event.geo)) {
      score += 15;
      reasons.push(`New region for this user (${event.geo})`);
    }
    if (vpn) {
      reasons.push(
        'New ASN and region not scored separately — a VPN changes both by design, and ' +
          'counting them as evidence would be counting the same fact three times'
      );
    }
  } else {
    reasons.push('No baseline yet for this mailbox — score is advisory');
  }

  // ── the adversary-in-the-middle signature ───────────────────────────────────
  // A relayable challenge issued AND passed from a network this user has never
  // used. This is what both confirmed takeovers looked like.
  const novelNetwork = baseline ? !!prefix && !baseline.knownPrefixes.includes(prefix) : true;
  if (relayable && novelNetwork) {
    score += 35;
    reasons.push(`Relayable MFA challenge (${challenge.trim()}) passed from an unfamiliar network`);
  }

  // ── infrastructure ──────────────────────────────────────────────────────────
  //
  // An ASN cannot answer this question on its own. AS13335 is Cloudflare, which carries
  // both WARP — a consumer privacy VPN that turns up on staff and student phones — and
  // genuine attacker proxying. Scoring the ASN alone flagged roughly 90 WARP sign-ins as
  // hosting infrastructure in a single backfill, which is how a flag queue stops being
  // read at all.
  //
  // RDAP names the registered owner of the netblock, which is the evidence the ASN does
  // not carry. When it has a decisive answer it OVERRIDES the ASN list. When RDAP is
  // absent or inconclusive, the ASN heuristic still applies — a missing lookup must not
  // silently downgrade a real datacenter sign-in.
  const datacenterAsn = !!event.asn && DATACENTER_ASNS.has(event.asn);

  if (net?.klass === 'anonymizer') {
    // A privacy relay is a weak signal, not a strong one: it is what a student on a
    // personal phone and a privacy-minded teacher both look like. It nudges the score so
    // that a novel VPN sign-in can still clear the threshold when combined with other
    // evidence, but it can no longer raise a flag by itself.
    score += 10;
    reasons.push(
      `Consumer VPN or privacy relay (${net.org ?? `AS${event.asn}`}) — ordinary on personal devices`
    );
  } else if (net?.klass === 'residential') {
    if (datacenterAsn) {
      reasons.push(
        `AS${event.asn} is shared infrastructure, but this netblock is registered to a ` +
          `consumer ISP (${net.org ?? 'unknown owner'}) — not scored as hosting`
      );
    }
  } else if (datacenterAsn) {
    score += 30;
    reasons.push(`Sign-in from hosting/VPN infrastructure (AS${event.asn}), not a consumer ISP`);
  }

  // ── sensitive action in the same breath ─────────────────────────────────────
  // Filter creation is the single highest-fidelity signal we have: across 31 risky-action
  // events in September it fired once, on the one account that was genuinely taken over.
  // "Allowing an app access to Google data" is routine ed-tech OAuth consent (30 of 31)
  // and must NOT score.
  if (event.sensitive && /filter/i.test(event.sensitive)) {
    score += 45;
    reasons.push(`Sensitive Gmail action at sign-in: ${event.sensitive}`);
  }

  // ── impossible travel ───────────────────────────────────────────────────────
  for (const other of recent) {
    if (other === event || other.eventName !== 'login_success') continue;
    const gapMin = Math.abs(event.ts.getTime() - other.ts.getTime()) / 60000;
    if (gapMin > 0 && gapMin < 15 && other.geo && event.geo && other.geo !== event.geo) {
      score += 25;
      reasons.push(
        `Region changed ${other.geo} → ${event.geo} in ${Math.round(gapMin)} min ` +
          '(may be carrier geolocation rather than travel — verify with the user)'
      );
      break;
    }
  }

  // ── phishing-resistant auth strongly reduces risk ───────────────────────────
  if (resistant) {
    score = Math.max(0, score - 60);
    reasons.push('Authenticated with a passkey/security key — cannot be relayed');
  }

  // Immature baselines produce noise; keep the finding but damp the score.
  if (baseline && !baseline.mature) score = Math.round(score * 0.6);

  return { score, reasons, flag: score >= threshold };
}

/** Severity band for the UI. */
export function band(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= FLAG_THRESHOLD) return 'medium';
  return 'low';
}
