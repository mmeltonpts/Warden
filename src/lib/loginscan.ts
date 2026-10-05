/**
 * Scheduled sign-in scan.
 *
 * Runs every 6 hours from a systemd timer. Pulls the Google login audit via GAM,
 * imports events, rebuilds each mailbox's baseline on a rolling window, scores the
 * new events against it, and raises risk flags for a human.
 *
 * Deliberately NOT automatic-remediation. Two of the three "suspicious" sign-ins that
 * looked most alarming in September turned out to be carrier geolocation artefacts.
 * An auto-suspend would have locked out staff mid-day on the strength of an AT&T IPv6
 * block that geolocates to Texas. This raises flags; people decide.
 */
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { mkdtemp, rm } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  buildBaseline,
  assessRisk,
  ipPrefix,
  type RawLoginEvent,
  type Baseline,
  type NetVerdict
} from './baseline';

/**
 * Defaults ONLY. The operative values come from Settings via ScanDeps.
 *
 * These used to be the operative values while the matching Settings fields were read by
 * nothing, so an admin could widen the lookback mid-incident, get a "Saved." banner, and
 * scan exactly the same window as before. `baselineWindowDays` was worse than dead: the
 * backfill script honoured it and the scheduled scan did not, so the history one built was
 * scored against a window the other never used.
 */
export const BASELINE_WINDOW_DAYS = 45;
export const SCAN_LOOKBACK_HOURS = 8;

export interface ScanDeps {
  gamPath: string;
  /** Insert events, ignoring duplicates. Returns how many were genuinely new. */
  upsertEvents: (events: RawLoginEvent[]) => Promise<number>;
  /** Events for one mailbox within the baseline window. */
  historyFor: (mailbox: string, since: Date) => Promise<RawLoginEvent[]>;
  loadBaseline: (mailbox: string) => Promise<Baseline | null>;
  saveBaseline: (b: Baseline, firstSeen?: Date, lastSeen?: Date) => Promise<void>;
  raiseFlag: (f: {
    mailbox: string;
    ts: Date;
    score: number;
    reasons: string[];
    ip?: string | null;
    asn?: string | null;
    geo?: string | null;
    challenge?: string | null;
    suspicious: boolean;
  }) => Promise<boolean>;
  /**
   * Who owns the netblock this IP sits in, from RDAP.
   *
   * Optional, and absence is not neutral by accident: without it the scorer falls back to
   * the datacenter-ASN list, which cannot tell Cloudflare WARP on a student's phone from
   * Cloudflare proxying an attack. That fallback over-flags rather than under-flags, so a
   * missing classifier is safe but noisy.
   *
   * Implementations must be cached — this is called once per scored event.
   */
  classifyIp?: (ip: string | null | undefined) => Promise<NetVerdict | null>;
  /** Settings → Sign-in risk. Undefined falls back to the built-in FLAG_THRESHOLD. */
  flagThreshold?: number;
  /** Settings → Sign-in risk. How far back each scan looks for new events. */
  lookbackHours?: number;
  /**
   * Settings → Sign-in risk. How much history a baseline learns from.
   *
   * Must match what backfill-logins.ts uses, or the two build and score against different
   * windows. Both now read the same setting.
   */
  baselineWindowDays?: number;
  /** Settings → Sign-in risk. Sign-ins located outside these are flagged on their own. */
  homeCountries?: string[];
}

/** Stream GAM's login report CSV rather than buffering it — 7 days is ~135k rows. */
/**
 * `gam report login` is TENANT-WIDE: it already returns every domain's events in one
 * paginated call. The domain filter below is therefore free — it decides what to keep,
 * not what to fetch.
 *
 * That matters, because this used to take a single `staffDomain` and discard everything
 * else. ~6,336 student mailboxes had their sign-in history pulled from Google and thrown
 * away on arrival, so student accounts had no baselines, no flags, and no coverage at all
 * — while the Risk page said it scored "each mailbox's own learned normal" over a count
 * that silently excluded them.
 */
export async function fetchLoginEvents(
  gamPath: string,
  since: Date,
  domains: string | string[]
): Promise<RawLoginEvent[]> {
  const suffixes = (Array.isArray(domains) ? domains : [domains])
    .filter(Boolean)
    .map((d) => `@${d.toLowerCase()}`);
  const dir = await mkdtemp(path.join(tmpdir(), 'warden-login-'));
  const csvPath = path.join(dir, 'login.csv');

  await new Promise<void>((resolve, reject) => {
    const out = createWriteStream(csvPath);
    const child = spawn(gamPath, ['report', 'login', 'start', since.toISOString()], {
      stdio: ['ignore', 'pipe', 'ignore']
    });
    child.stdout.pipe(out);
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`gam exit ${code}`))));
  });

  const events: RawLoginEvent[] = [];
  let header: string[] | null = null;
  const rl = createInterface({ input: createReadStream(csvPath), crlfDelay: Infinity });

  for await (const line of rl) {
    const cols = parseCsvLine(line);
    if (!header) {
      header = cols;
      continue;
    }
    const row: Record<string, string> = {};
    header.forEach((h, i) => (row[h] = cols[i] ?? ''));

    const mailbox = (row['actor.email'] ?? '').toLowerCase();
    if (!suffixes.some((sfx) => mailbox.endsWith(sfx))) continue;
    const tsRaw = row['id.time'];
    if (!tsRaw) continue;

    events.push({
      mailbox,
      ts: new Date(tsRaw),
      eventName: row['name'] ?? '',
      ip: row['ipAddress'] || null,
      asn: row['networkInfo.ipAsn.0'] || row['networkInfo.ipAsn'] || null,
      geo: row['networkInfo.subdivisionCode'] || null,
      challenge: row['login_challenge_method'] || null,
      suspicious: String(row['is_suspicious']).toLowerCase() === 'true',
      sensitive: row['sensitive_action_name'] || null
    });
  }

  await rm(dir, { recursive: true, force: true });
  return events;
}

/** Minimal RFC4180 splitter — GAM quotes fields containing commas. */
export function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') inQ = false;
      else cur += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out;
}

export interface ScanResult {
  windowStart: Date;
  windowEnd: Date;
  eventsSeen: number;
  eventsNew: number;
  baselinesRebuilt: number;
  flagsRaised: number;
}

export interface ScoredFlag {
  ts: Date;
  score: number;
  reasons: string[];
  ip?: string | null;
  asn?: string | null;
  geo?: string | null;
  challenge?: string | null;
  suspicious?: boolean;
}

/**
 * Collapse a mailbox's flagged sign-ins so that repeated hits from the SAME network in one
 * scan become a single flag. A phone that re-authenticates several times a minute against
 * one new Wi-Fi or VPN exit produces several events with an identical risk signature; left
 * alone they become several identical rows in the queue and several identical lines in the
 * notification email. This is the same "one fact, not many" idea as the VPN-triple rule.
 *
 * Grouping is by network (the /24 or /48 prefix, falling back to the raw IP). The kept flag
 * is the worst-scoring one in the group — so a suspicious sign-in is never hidden behind a
 * benign one — and its reasons gain a line stating how many sign-ins it represents. Separate
 * networks are never merged, so two genuinely different flags for one person still show.
 */
export function collapseByNetwork(flags: ScoredFlag[]): ScoredFlag[] {
  const groups = new Map<string, ScoredFlag[]>();
  for (const f of flags) {
    const key = ipPrefix(f.ip) ?? f.ip ?? 'unknown';
    const g = groups.get(key);
    if (g) g.push(f);
    else groups.set(key, [f]);
  }
  const out: ScoredFlag[] = [];
  for (const g of groups.values()) {
    if (g.length === 1) { out.push(g[0]); continue; }
    const top = g.reduce((a, b) => (b.score > a.score ? b : a));
    out.push({
      ...top,
      reasons: [...top.reasons, `${g.length} sign-ins from this network in this scan — collapsed to one flag`]
    });
  }
  return out.sort((a, b) => b.score - a.score || a.ts.getTime() - b.ts.getTime());
}

export async function runLoginScan(
  deps: ScanDeps,
  domains: string | string[]
): Promise<ScanResult> {
  const now = new Date();
  const lookbackHours = deps.lookbackHours ?? SCAN_LOOKBACK_HOURS;
  const baselineDays = deps.baselineWindowDays ?? BASELINE_WINDOW_DAYS;
  const windowStart = new Date(now.getTime() - lookbackHours * 3600_000);
  const baselineSince = new Date(now.getTime() - baselineDays * 86400_000);

  const events = await fetchLoginEvents(deps.gamPath, windowStart, domains);
  const eventsNew = await deps.upsertEvents(events);

  // Group the window's events by mailbox; only touch mailboxes that were active.
  const byMailbox = new Map<string, RawLoginEvent[]>();
  for (const e of events) {
    const list = byMailbox.get(e.mailbox) ?? [];
    list.push(e);
    byMailbox.set(e.mailbox, list);
  }

  let baselinesRebuilt = 0;
  let flagsRaised = 0;

  for (const [mailbox, windowEvents] of byMailbox) {
    const history = await deps.historyFor(mailbox, baselineSince);

    // Score against the baseline as it was BEFORE this window's events were learned,
    // otherwise an intrusion teaches the baseline that the intruder is normal.
    const windowKeys = new Set(windowEvents.map((e) => `${e.ts.toISOString()}|${e.eventName}`));
    const prior = history.filter((h) => !windowKeys.has(`${h.ts.toISOString()}|${h.eventName}`));
    const priorBaseline = prior.length ? buildBaseline(mailbox, prior) : await deps.loadBaseline(mailbox);

    const flaggedThisMailbox: ScoredFlag[] = [];
    for (const e of windowEvents) {
      // Best-effort. RDAP being slow or down must degrade the score's precision, never
      // fail the scan — the ASN fallback still catches real hosting.
      const net = deps.classifyIp ? await deps.classifyIp(e.ip).catch(() => null) : null;
      const { score, reasons, flag } = assessRisk(
        e,
        priorBaseline,
        windowEvents,
        net,
        deps.flagThreshold,
        deps.homeCountries
      );
      if (flag) {
        flaggedThisMailbox.push({
          ts: e.ts, score, reasons,
          ip: e.ip, asn: e.asn, geo: e.geo, challenge: e.challenge, suspicious: !!e.suspicious
        });
      }
    }

    // A burst of sign-ins from one network is one fact, not many. A phone re-authing four
    // times in a minute against the same new Wi-Fi/VPN exit produced four identical flags
    // (same score, same reasons) that filled the queue and the notification email. Collapse
    // them to one per network, keeping the worst and noting the repeat count.
    for (const f of collapseByNetwork(flaggedThisMailbox)) {
      const created = await deps.raiseFlag({
        mailbox, ts: f.ts, score: f.score, reasons: f.reasons,
        ip: f.ip, asn: f.asn, geo: f.geo, challenge: f.challenge, suspicious: !!f.suspicious
      });
      if (created) flagsRaised++;
    }

    // Now fold the window in and persist the updated normal.
    const fresh = buildBaseline(mailbox, history);
    const times = history.map((h) => h.ts.getTime()).sort((a, b) => a - b);
    await deps.saveBaseline(
      fresh,
      times.length ? new Date(times[0]) : undefined,
      times.length ? new Date(times[times.length - 1]) : undefined
    );
    baselinesRebuilt++;
  }

  return {
    windowStart,
    windowEnd: now,
    eventsSeen: events.length,
    eventsNew,
    baselinesRebuilt,
    flagsRaised
  };
}

export { ipPrefix };
