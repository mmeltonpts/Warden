/**
 * KnowBe4 integration — two directions, two different APIs, two different keys.
 *
 *   PUSH  User Events API   Warden -> KSAT. Real compromise events raise the user's risk
 *                           score and drive SecurityCoach, instead of a real click being
 *                           invisible to the training platform. This is the valuable half.
 *
 *   PULL  Reporting API v1  KSAT -> Warden. Phish-prone percentage as a risk multiplier:
 *                           someone who fails simulations is likelier to fail the real one.
 *
 * On verification: the Reporting API v1 shape below is well documented and stable. The
 * User Events endpoint and payload were NOT verifiable — developer.knowbe4.com is
 * JavaScript-rendered and returns only a page title to a fetch. So the URL, the field
 * names, and the HTTP method are all configurable settings with defaults, and a failed
 * push is logged rather than thrown. If KnowBe4's schema differs, it is a settings edit,
 * not a code change.
 *
 * Nothing here is ever on the critical path. A dead key, an expired token or a KnowBe4
 * outage must not stop a sweep.
 */
import { errText } from './errors';

export type Kb4Status = 'ok' | 'disabled' | 'unauthorized' | 'rate_limited' | 'error';

export interface Kb4Result<T = unknown> {
  status: Kb4Status;
  data?: T;
  httpStatus?: number;
  error?: string;
}

export interface Kb4Settings {
  enabled: boolean;
  /** Reporting API v1. Region-specific: us / eu / ca / uk / de. */
  reportingBaseUrl: string;
  reportingToken: string;
  /** User Events API — push. */
  userEventsEnabled: boolean;
  userEventsUrl: string;
  userEventsToken: string;
  /** Event type names as configured in the KSAT console. */
  eventTypes: {
    compromise: string;
    realPhishClick: string;
    persistenceFound: string;
    campaignRecipient: string;
  };
  timeoutSeconds: number;
}

export const KB4_DEFAULTS: Kb4Settings = {
  enabled: false,
  reportingBaseUrl: 'https://us.api.knowbe4.com/v1',
  reportingToken: '',
  userEventsEnabled: false,
  userEventsUrl: 'https://api.events.knowbe4.com/events',
  userEventsToken: '',
  eventTypes: {
    compromise: 'Warden: Account Takeover Confirmed',
    realPhishClick: 'Warden: Clicked Real Phishing Link',
    persistenceFound: 'Warden: Attacker Persistence Found',
    campaignRecipient: 'Warden: Received Live Phishing Campaign'
  },
  timeoutSeconds: 20
};

async function call<T>(
  url: string,
  token: string,
  init: RequestInit,
  timeoutSeconds: number
): Promise<Kb4Result<T>> {
  if (!token) return { status: 'disabled', error: 'no token configured' };

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutSeconds * 1000);
  try {
    const res = await fetch(url, {
      ...init,
      signal: ac.signal,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(init.headers ?? {})
      }
    });

    if (res.status === 401 || res.status === 403) {
      return { status: 'unauthorized', httpStatus: res.status };
    }
    if (res.status === 429) {
      return { status: 'rate_limited', httpStatus: 429 };
    }
    if (!res.ok) {
      return { status: 'error', httpStatus: res.status, error: (await res.text()).slice(0, 300) };
    }
    const text = await res.text();
    return { status: 'ok', httpStatus: res.status, data: (text ? JSON.parse(text) : null) as T };
  } catch (e) {
    return { status: 'error', error: errText(e) };
  } finally {
    clearTimeout(timer);
  }
}

// ─── PULL: Reporting API v1 ──────────────────────────────────────────────────

export interface Kb4User {
  id: number;
  email: string;
  first_name?: string;
  last_name?: string;
  /** 0..150 observed on this tenant — KnowBe4 allows >100. A prior, not evidence. */
  phish_prone_percentage?: number;
  status?: string;
  groups?: number[];
  job_title?: string;
  department?: string;
  division?: string;
  location?: string;
  manager_email?: string | null;
  manager_name?: string | null;
  employee_number?: string;
  current_risk_score?: number;
  aliases?: string[];
  provisioning_managed?: boolean;
  joined_on?: string;
  last_sign_in?: string | null;
}

const MAX_PAGES = 20;
const PER_PAGE = 500;

/**
 * Paginated roster. 500/page is the documented maximum.
 *
 * `status: 'ok'` means COMPLETE, and callers rely on that. `sync-knowbe4.ts` treats any
 * user absent from an 'ok' roster as having left KnowBe4 and removes them.
 *
 * This previously returned `{ status: 'ok', data: all }` on a rate-limit part-way through
 * pagination. A 429 on page four of six would have reported success with 1,500 of 2,644
 * users, and the sync would then have deleted eleven hundred real people from the mirror.
 * A partial result must never be indistinguishable from a complete one.
 */
export async function fetchUsers(s: Kb4Settings): Promise<Kb4Result<Kb4User[]>> {
  if (!s.enabled) return { status: 'disabled' };
  const all: Kb4User[] = [];
  let complete = false;

  for (let page = 1; page <= MAX_PAGES; page++) {
    const r = await call<Kb4User[]>(
      `${s.reportingBaseUrl}/users?page=${page}&per_page=${PER_PAGE}`,
      s.reportingToken,
      { method: 'GET' },
      s.timeoutSeconds
    );
    // Hand back what we have so the caller can still refresh it, but keep the real status.
    if (r.status !== 'ok') return { ...r, data: all.length ? all : undefined };
    const batch = r.data ?? [];
    all.push(...batch);
    if (batch.length < PER_PAGE) {
      complete = true;
      break;
    }
  }

  // Exhausting MAX_PAGES on a full final page means there is more we did not fetch.
  // Returning 'ok' here would be the same truncation arriving by a different route.
  if (!complete) {
    return {
      status: 'error',
      data: all,
      error: `roster exceeds ${MAX_PAGES * PER_PAGE} users — pagination truncated at ${all.length}`
    };
  }
  return { status: 'ok', data: all };
}

/**
 * email -> phish-prone percentage.
 *
 * Used as a RISK MULTIPLIER, never as a standalone finding. A high PPP is a prior, not
 * evidence: it says this person is likelier to fall for something, not that they did.
 */
export async function fetchPhishProneMap(s: Kb4Settings): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const r = await fetchUsers(s);
  if (r.status !== 'ok' || !r.data) return out;
  for (const u of r.data) {
    if (u.email && typeof u.phish_prone_percentage === 'number') {
      out.set(u.email.toLowerCase(), u.phish_prone_percentage);
    }
  }
  return out;
}

/**
 * Score adjustment from phish-prone percentage. Deliberately small and capped.
 *
 * Doug Johnson clicked a real payload. If his PPP had nudged him up the queue before the
 * takeover rather than after, that is the whole value. But a training metric must never
 * be able to manufacture a finding on its own — capped at +12, and it cannot lift a score
 * from below the threshold to above it by itself.
 */
export function phishProneAdjustment(ppp: number | undefined): { delta: number; reason?: string } {
  if (ppp === undefined) return { delta: 0 };
  if (ppp >= 40) return { delta: 12, reason: `High phish-prone percentage (${ppp}%) in KnowBe4` };
  if (ppp >= 20) return { delta: 7, reason: `Elevated phish-prone percentage (${ppp}%) in KnowBe4` };
  if (ppp >= 10) return { delta: 3, reason: `Phish-prone percentage ${ppp}% in KnowBe4` };
  return { delta: 0 };
}

export interface Kb4Account {
  name: string;
  type?: string;
  domains?: string[];
  admins?: Array<{ id: number; first_name: string | null; last_name: string | null; email: string }>;
  subscription_level?: string;
  subscription_end_date?: string;
  number_of_seats?: number;
  current_risk_score?: number;
}

/** GET /account. One cheap call; carries subscription tier, seat count and account risk. */
export async function fetchAccount(s: Kb4Settings): Promise<Kb4Result<Kb4Account>> {
  if (!s.enabled) return { status: 'disabled' };
  return call<Kb4Account>(`${s.reportingBaseUrl}/account`, s.reportingToken, { method: 'GET' }, s.timeoutSeconds);
}

export interface Kb4SecurityTest {
  campaign_id: number;
  pst_id: number;
  name: string;
  status?: string;
  phish_prone_percentage?: number;
  started_at?: string;
  duration?: number;
}

/**
 * GET /phishing/security_tests — simulated phishing campaigns.
 *
 * Verified on this tenant 2026-09-23: exactly one test exists, named "Test", started
 * 2021-01-18, closed, 0.0% phish-prone. This district does not currently run simulations,
 * which is worth stating plainly rather than rendering an empty chart.
 */
export async function fetchSecurityTests(s: Kb4Settings): Promise<Kb4Result<Kb4SecurityTest[]>> {
  if (!s.enabled) return { status: 'disabled' };
  return call<Kb4SecurityTest[]>(
    `${s.reportingBaseUrl}/phishing/security_tests`,
    s.reportingToken,
    { method: 'GET' },
    s.timeoutSeconds
  );
}

// ─── PUSH: User Events API ───────────────────────────────────────────────────

export interface Kb4EventInput {
  targetEmail: string;
  eventType: string;
  description?: string;
  riskLevel?: number; // KnowBe4 convention: -10..10, higher = riskier
  occurredAt?: Date;
  externalId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * KnowBe4 caps `external_id` at 64 characters.
 *
 * The obvious id — `warden-compromise-<email>-<ISO timestamp>` — overruns that, and a naive
 * slice would cut the timestamp off the end and collapse distinct events onto one id, which
 * is worse than a rejected request because it silently loses events.
 */
export function externalId(prefix: string, mailbox: string, when: Date): string {
  const stamp = when.toISOString().replace(/[-:T]/g, '').slice(0, 14); // YYYYMMDDHHMMSS
  const local = mailbox.split('@')[0].replace(/[^a-z0-9.]/gi, '').slice(0, 30);
  return `${prefix}-${local}-${stamp}`.slice(0, 64);
}

/**
 * Field limits come from the published User Events swagger, checked 2026-09-23:
 *   occurred_date  format `date` — YYYY-MM-DD, NOT a full ISO 8601 timestamp
 *   description    max 255
 *   external_id    max 64
 *
 * `risk_level` is marked deprecated in that spec and is replaced by `factor`. It is still
 * sent for now because removing it has not been verified as safe, but be aware that the
 * deliberate 10/9/10/3 weighting in the builders below currently has no effect on the
 * KnowBe4 risk score.
 */
function eventBody(e: Kb4EventInput) {
  return {
    target_user: e.targetEmail,
    event_type: e.eventType,
    description: e.description?.slice(0, 255),
    risk_level: e.riskLevel ?? 5,
    occurred_date: (e.occurredAt ?? new Date()).toISOString().slice(0, 10),
    external_id: e.externalId?.slice(0, 64),
    ...(e.metadata ?? {})
  };
}

export async function pushEvent(s: Kb4Settings, e: Kb4EventInput): Promise<Kb4Result> {
  if (!s.enabled || !s.userEventsEnabled) return { status: 'disabled' };
  return call(
    s.userEventsUrl,
    s.userEventsToken,
    { method: 'POST', body: JSON.stringify(eventBody(e)) },
    s.timeoutSeconds
  );
}

/** Batched. Falls back to individual posts if the endpoint rejects an array. */
export async function pushEvents(s: Kb4Settings, events: Kb4EventInput[]): Promise<Kb4Result> {
  if (!s.enabled || !s.userEventsEnabled) return { status: 'disabled' };
  if (!events.length) return { status: 'ok' };

  const batch = await call(
    s.userEventsUrl,
    s.userEventsToken,
    { method: 'POST', body: JSON.stringify(events.map(eventBody)) },
    s.timeoutSeconds
  );
  if (batch.status === 'ok' || batch.status === 'unauthorized') return batch;

  let okCount = 0;
  for (const e of events) {
    const r = await pushEvent(s, e);
    if (r.status === 'ok') okCount++;
  }
  return okCount === events.length
    ? { status: 'ok' }
    : { status: 'error', error: `${okCount}/${events.length} events accepted` };
}

// ─── the events Warden actually raises ───────────────────────────────────────

export function compromiseEvent(s: Kb4Settings, mailbox: string, detail: string, when: Date): Kb4EventInput {
  return {
    targetEmail: mailbox,
    eventType: s.eventTypes.compromise,
    description: `Account takeover confirmed by Warden. ${detail}`.slice(0, 255),
    riskLevel: 10,
    occurredAt: when,
    externalId: externalId('wrd-cmp', mailbox, when)
  };
}

export function realClickEvent(s: Kb4Settings, mailbox: string, payloadHost: string, when: Date): Kb4EventInput {
  return {
    targetEmail: mailbox,
    eventType: s.eventTypes.realPhishClick,
    description: `Clicked a live phishing payload (${payloadHost}) — not a simulation.`.slice(0, 255),
    riskLevel: 9,
    occurredAt: when,
    externalId: externalId('wrd-clk', mailbox, when)
  };
}

export function persistenceEvent(s: Kb4Settings, mailbox: string, what: string, when: Date): Kb4EventInput {
  return {
    targetEmail: mailbox,
    eventType: s.eventTypes.persistenceFound,
    description: `Attacker persistence found on this account: ${what}`.slice(0, 255),
    riskLevel: 10,
    occurredAt: when,
    externalId: externalId('wrd-per', mailbox, when)
  };
}

export function recipientEvent(s: Kb4Settings, mailbox: string, campaign: string, when: Date): Kb4EventInput {
  return {
    targetEmail: mailbox,
    eventType: s.eventTypes.campaignRecipient,
    description: `Received a live phishing campaign (${campaign}). Exposure, not compromise.`.slice(0, 255),
    riskLevel: 3,
    occurredAt: when,
    externalId: `wrd-rcp-${mailbox.split('@')[0].slice(0, 24)}-${campaign.slice(0, 28)}`
  };
}

/** Base URL of the events service, derived from the configured POST endpoint. */
function eventsBase(s: Kb4Settings): string {
  return s.userEventsUrl.replace(/\/events\/?$/, '');
}

/**
 * Event types defined in the KSAT console.
 *
 * Verified against the live tenant on 2026-09-23: `GET /event_types` returned
 * `{"data":[],"meta":{"count":0}}`. This district has ZERO event types defined, so every
 * event Warden pushes names a type that does not exist. Reporting that is the difference
 * between "integration configured" and "integration working".
 */
export async function listEventTypes(s: Kb4Settings): Promise<Kb4Result<string[]>> {
  if (!s.enabled || !s.userEventsEnabled) return { status: 'disabled' };
  const r = await call<{ data?: Array<{ name?: string }> }>(
    `${eventsBase(s)}/event_types`,
    s.userEventsToken,
    { method: 'GET' },
    s.timeoutSeconds
  );
  if (r.status !== 'ok') return { status: r.status, httpStatus: r.httpStatus, error: r.error };
  return {
    status: 'ok',
    httpStatus: r.httpStatus,
    data: (r.data?.data ?? []).map((t) => t.name ?? '').filter(Boolean)
  };
}

/**
 * Settings-page probe. Distinguishes "no key" from "bad key" from "right key, wrong product".
 *
 * This previously reported userEvents as 'ok' whenever the token string was non-empty,
 * without ever contacting KnowBe4 — a green light that asserted nothing. On 2026-09-23 the
 * saved reporting token turned out to be a KCM (Compliance Manager) key returning 401 on
 * every KSAT endpoint, and no amount of string-length checking would have surfaced that.
 * Both halves now make a real request.
 *
 * GET, never POST. Posting a probe event would create a real risk-score entry against a
 * real staff member.
 */
export async function kb4Health(s: Kb4Settings): Promise<{
  reporting: Kb4Result;
  userEvents: Kb4Result;
  eventTypes: { defined: string[]; missing: string[] } | null;
}> {
  const reporting = s.enabled
    ? await call(`${s.reportingBaseUrl}/account`, s.reportingToken, { method: 'GET' }, 10)
    : ({ status: 'disabled' } as Kb4Result);

  if (!s.enabled || !s.userEventsEnabled) {
    return { reporting, userEvents: { status: 'disabled' }, eventTypes: null };
  }
  if (!s.userEventsToken) {
    return {
      reporting,
      userEvents: { status: 'unauthorized', error: 'no token configured' },
      eventTypes: null
    };
  }

  const userEvents = await call(
    `${eventsBase(s)}/events?limit=1`,
    s.userEventsToken,
    { method: 'GET' },
    10
  );
  if (userEvents.status !== 'ok') return { reporting, userEvents, eventTypes: null };

  // Auth is good — now check the types we intend to push against what actually exists.
  const types = await listEventTypes(s);
  const defined = types.status === 'ok' ? types.data ?? [] : [];
  const want = Object.values(s.eventTypes ?? {});
  return {
    reporting,
    userEvents,
    eventTypes: { defined, missing: want.filter((w) => !defined.includes(w)) }
  };
}
