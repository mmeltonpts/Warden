/**
 * CrowdStrike Falcon API — read-only.
 *
 * Endpoint detections are the attacks mail filtering never sees: on 2026-10-01 Falcon
 * blocked a pasted PowerShell that would have silently installed a rogue ScreenConnect
 * client on a staff PC. Nothing about it passed through Gmail.
 *
 * Scope is deliberately limited to Alerts:Read and Hosts:Read. Real Time Response is never
 * requested: it executes commands on every endpoint, and a capability Warden holds is a
 * capability anyone who steals a Warden session holds.
 */
import { errText } from './errors';

export const FALCON_CLOUDS: Record<string, string> = {
  'us-1': 'https://api.crowdstrike.com',
  'us-2': 'https://api.us-2.crowdstrike.com',
  'eu-1': 'https://api.eu-1.crowdstrike.com',
  'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com',
  'us-gov-2': 'https://api.us-gov-2.crowdstrike.mil'
};

export interface FalconSettings {
  enabled: boolean;
  cloud: string;
  clientId: string;
  clientSecret: string;
}

/**
 * Accepts a cloud name (us-1, us-gov-1 …) OR the API base URL as Falcon shows it
 * (https://api.laggar.gcw.crowdstrike.com). Operators copy the URL from the API-client
 * page; making them translate it into a code name is how a GovCloud key ended up being
 * sent to the commercial cloud and rejected with a bare HTTP 400.
 *
 * A URL is only accepted if it is one of CrowdStrike's own API hosts — this setting must
 * never become a way to send the client secret somewhere else.
 */
export function falconBase(cloud: string): string | null {
  const v = (cloud || '').trim().toLowerCase().replace(/\/+$/, '');
  if (FALCON_CLOUDS[v]) return FALCON_CLOUDS[v];
  const known = Object.values(FALCON_CLOUDS).find((u) => u === v || u === `https://${v}`);
  return known ?? null;
}

/**
 * The Falcon CONSOLE (UI) base for a cloud, derived from the API base: every cloud's console
 * host is its API host with `api.` swapped for `falcon.` (api.crowdstrike.com →
 * falcon.crowdstrike.com, api.laggar.gcw.crowdstrike.com → falcon.laggar.gcw.crowdstrike.com).
 * Returns null for an unknown cloud, so a link is only ever built to a real CrowdStrike host.
 */
export function falconConsole(cloud: string): string | null {
  const base = falconBase(cloud);
  return base ? base.replace('://api.', '://falcon.') : null;
}

/**
 * A read-only deep-link into the Falcon console for a host, so an analyst can jump straight
 * to where Network Containment lives. Warden never contains a host itself — it requests only
 * Alerts:Read and Hosts:Read — so this is a hand-off, not an action. Prefers the host-detail
 * page by device id (where the Contain action is); null when neither cloud nor device is known.
 */
export function falconHostLink(cloud: string, deviceId?: string | null): string | null {
  const console = falconConsole(cloud);
  if (!console) return null;
  return deviceId
    ? `${console}/host-management/hosts/${encodeURIComponent(deviceId)}`
    : `${console}/host-management/hosts-inventory`;
}

/** Falcon errors look like {"errors":[{"message":"…"}]}. Return the message, not the envelope. */
async function falconError(r: Response): Promise<string> {
  const t = await r.text();
  try {
    const j = JSON.parse(t) as { errors?: Array<{ message?: string }> };
    const m = j.errors?.map((e) => e.message).filter(Boolean).join('; ');
    if (m) return `HTTP ${r.status}: ${m}`;
  } catch { /* not JSON */ }
  return `HTTP ${r.status}: ${t.slice(0, 300)}`;
}

async function req(url: string, init: RequestInit, timeoutMs = 20_000): Promise<Response> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

/** OAuth2 client-credentials. Tokens last 30 minutes; callers fetch one per run. */
export async function falconToken(s: FalconSettings): Promise<{ token?: string; error?: string }> {
  const base = falconBase(s.cloud);
  if (!base) return { error: `unknown cloud "${s.cloud}" — use one of ${Object.keys(FALCON_CLOUDS).join(', ')}` };
  if (!s.clientId || !s.clientSecret) return { error: 'client ID or secret not set' };
  try {
    const r = await req(`${base}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ client_id: s.clientId, client_secret: s.clientSecret }).toString()
    });
    if (r.status === 401 || r.status === 403) {
      return { error: `HTTP ${r.status} — the ID/secret were rejected. Check the cloud matches the console the key came from.` };
    }
    if (!r.ok) {
      const msg = await falconError(r);
      return { error: r.status === 400 ? `${msg} — usually the cloud is wrong for this key (a GovCloud key sent to us-1, or the reverse)` : msg };
    }
    const j = (await r.json()) as { access_token?: string };
    return j.access_token ? { token: j.access_token } : { error: 'no access_token in response' };
  } catch (e) {
    return { error: errText(e) };
  }
}

export interface ScopeCheck {
  scope: string;
  ok: boolean;
  detail: string;
}

/**
 * Prove each scope with a real read. A 403 here means the API client exists but was not
 * granted that scope — said plainly, because "connected" with a missing scope is exactly
 * the false green light the KnowBe4 health check once gave by testing that a token string
 * was non-empty.
 */
export async function falconHealth(s: FalconSettings): Promise<{ token: ScopeCheck; scopes: ScopeCheck[] }> {
  const t = await falconToken(s);
  if (!t.token) return { token: { scope: 'Authentication', ok: false, detail: t.error ?? 'failed' }, scopes: [] };
  const base = falconBase(s.cloud)!;
  const auth = { Authorization: `Bearer ${t.token}`, Accept: 'application/json' };

  const probe = async (scope: string, path: string): Promise<ScopeCheck> => {
    try {
      const r = await req(`${base}${path}`, { headers: auth });
      if (r.status === 403) return { scope, ok: false, detail: 'HTTP 403 — scope not granted on this API client' };
      if (!r.ok) return { scope, ok: false, detail: await falconError(r) };
      const j = (await r.json()) as { meta?: { pagination?: { total?: number } } };
      const total = j.meta?.pagination?.total;
      return { scope, ok: true, detail: total !== undefined ? `readable — ${total.toLocaleString()} records` : 'readable' };
    } catch (e) {
      return { scope, ok: false, detail: errText(e) };
    }
  };

  return {
    token: { scope: 'Authentication', ok: true, detail: `token issued by ${base.replace('https://', '')}` },
    scopes: await Promise.all([
      probe('Alerts: Read', '/alerts/queries/alerts/v2?limit=1'),
      probe('Hosts: Read', '/devices/queries/devices/v1?limit=1')
    ])
  };
}

/** Authenticated client. Throws with Falcon's own error message. Read-only calls only. */
export async function falconClient(s: FalconSettings) {
  const t = await falconToken(s);
  if (!t.token) throw new Error(t.error ?? 'no token');
  const base = falconBase(s.cloud)!;
  const H = { Authorization: `Bearer ${t.token}`, Accept: 'application/json', 'Content-Type': 'application/json' };
  const call = async <T>(path: string, init: RequestInit = {}): Promise<T> => {
    const r = await req(`${base}${path}`, { ...init, headers: H }, 45_000);
    if (!r.ok) throw new Error(await falconError(r));
    return (await r.json()) as T;
  };
  return {
    async alertIds(filter: string, offset: number, limit = 500) {
      const j = await call<{ resources?: string[]; meta?: { pagination?: { total?: number } } }>(
        `/alerts/queries/alerts/v2?limit=${limit}&offset=${offset}&sort=updated_timestamp.asc&filter=${encodeURIComponent(filter)}`
      );
      return { ids: j.resources ?? [], total: j.meta?.pagination?.total ?? 0 };
    },
    async alerts(ids: string[]): Promise<unknown[]> {
      const out: unknown[] = [];
      for (let i = 0; i < ids.length; i += 100) {
        const j = await call<{ resources?: unknown[] }>('/alerts/entities/alerts/v2', {
          method: 'POST',
          body: JSON.stringify({ composite_ids: ids.slice(i, i + 100) })
        });
        out.push(...(j.resources ?? []));
      }
      return out;
    },
    /**
     * Per-host sign-in history. `combined/devices/login-history/v1` — the `queries` variant
     * returns 404 on this tenant. Covered by Hosts: Read.
     */
    async loginHistory(deviceIds: string[]) {
      const out = new Map<string, Array<{ user: string; at: Date }>>();
      for (let i = 0; i < deviceIds.length; i += 100) {
        const j = await call<{ resources?: Array<{ device_id?: string; recent_logins?: Array<{ user_name?: string; login_time?: string }> }> }>(
          '/devices/combined/devices/login-history/v1',
          { method: 'POST', body: JSON.stringify({ ids: deviceIds.slice(i, i + 100) }) }
        );
        for (const r of j.resources ?? []) {
          if (!r.device_id) continue;
          out.set(
            r.device_id,
            (r.recent_logins ?? [])
              .filter((l) => l.user_name && l.login_time)
              .map((l) => ({ user: l.user_name!, at: new Date(l.login_time!) }))
          );
        }
      }
      return out;
    },

    /**
     * Installed remote-access tools across the estate, from Falcon's application inventory
     * (`discover/combined/applications/v1`, facets host_info + install_usage — "usage" is
     * rejected on this tenant). One OR'd filter for the whole watch list, not a call per tool.
     */
    async applications(watch: string[]) {
      const terms = watch.map((w) => `name:*'*${w.replace(/'/g, '')}*'`).join(',');
      type App = {
        id?: string; name: string; version?: string; last_used_user_name?: string; last_used_user_sid?: string;
        last_used_timestamp?: string; last_used_file_name?: string; host?: { hostname?: string; last_seen_date?: string };
      };
      const out = new Map<string, App>();
      // Cursor pagination. This endpoint IGNORES `offset` — the first version looped on
      // offset, got page one back every time, and rendered 4,850 copies of one record.
      // De-duplicated on id as well, so a misbehaving cursor cannot inflate the table.
      let after: string | undefined;
      for (let page = 0; page < 50; page++) {
        const j = await call<{ resources?: App[]; meta?: { pagination?: { after?: string } } }>(
          `/discover/combined/applications/v1?limit=100&facet=host_info&facet=install_usage` +
            `&filter=${encodeURIComponent(`(${terms})`)}${after ? `&after=${encodeURIComponent(after)}` : ''}`
        );
        const before = out.size;
        for (const a of j.resources ?? []) out.set(a.id ?? `${a.host?.hostname}|${a.name}|${a.version}`, a);
        after = j.meta?.pagination?.after;
        if (!after || out.size === before) break;
      }
      return [...out.values()];
    },

    /** Containment state and last check-in, by hostname. */
    async devices(hostnames: string[]) {
      const out = new Map<string, { status: string; lastSeen: string | null; deviceId: string | null }>();
      for (const h of hostnames) {
        const q = await call<{ resources?: string[] }>(
          `/devices/queries/devices/v1?filter=${encodeURIComponent(`hostname:'${h.replace(/'/g, '')}'`)}`
        );
        if (!q.resources?.length) continue;
        const d = await call<{ resources?: Array<{ device_id?: string; status?: string; last_seen?: string }> }>(
          `/devices/entities/devices/v2?ids=${q.resources.map(encodeURIComponent).join('&ids=')}`
        );
        const x = (d.resources ?? []).sort((a, b) => String(b.last_seen).localeCompare(String(a.last_seen)))[0];
        // device_id drives the Falcon console deep-link (falconHostLink) so an analyst lands on
        // the host where Network Containment lives. Fall back to the query id when the entity
        // omits it.
        if (x) out.set(h, { status: x.status ?? 'unknown', lastSeen: x.last_seen ?? null, deviceId: x.device_id ?? q.resources[0] ?? null });
      }
      return out;
    }
  };
}
