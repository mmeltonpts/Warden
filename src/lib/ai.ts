/**
 * Optional Claude triage.
 *
 * Warden runs the Claude Code CLI as a subprocess under the `warden` system user,
 * using that user's own Claude Code session. There is no API key.
 *
 * Consequences of that choice, handled here rather than discovered at 22:00:
 *
 *   - The session expires. When it does, every call in this file fails and the
 *     console falls back to manual triage. Nothing else in Warden is affected:
 *     scope, sweep, verify and account-check never touch this module.
 *   - Re-authenticating needs an interactive browser flow on a headless box:
 *       ssh -L 8765:localhost:8765 warden-host
 *       sudo -u warden -H claude   # then follow the URL
 *   - Calls are serialised. Concurrency against one interactive session is a good
 *     way to get rate-limited mid-incident.
 *
 * Everything here is advisory. A model verdict never gates a sweep — a human does.
 */
import { spawn } from 'node:child_process';

export type AiStatus = 'ok' | 'disabled' | 'unavailable' | 'timeout' | 'bad_output';

export interface AiResult<T> {
  status: AiStatus;
  data?: T;
  raw?: string;
  error?: string;
}

export interface AiSettings {
  enabled: boolean;
  command: string[]; // e.g. ["claude","-p","{prompt}","--output-format","json"]
  timeoutSeconds: number;
}

/** One at a time. See note above. */
let chain: Promise<unknown> = Promise.resolve();
function serialise<T>(fn: () => Promise<T>): Promise<T> {
  const next = chain.then(fn, fn);
  chain = next.catch(() => undefined);
  return next as Promise<T>;
}

async function invoke(settings: AiSettings, prompt: string): Promise<AiResult<string>> {
  if (!settings.enabled) return { status: 'disabled' };

  const [bin, ...rest] = settings.command;
  const args = rest.map((a) => a.replace('{prompt}', prompt));

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch {
      return resolve({ status: 'unavailable', error: `cannot spawn ${bin}` });
    }

    let out = '';
    let err = '';
    let done = false;

    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      child.kill('SIGKILL');
      resolve({ status: 'timeout' });
    }, settings.timeoutSeconds * 1000);

    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));

    child.on('error', () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ status: 'unavailable', error: `cannot spawn ${bin}` });
    });

    child.on('close', (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (code !== 0) {
        // Most often: the session expired. Surfaced to the UI as "AI unavailable".
        return resolve({ status: 'unavailable', error: err.slice(0, 500) || `exit ${code}` });
      }
      resolve({ status: 'ok', raw: out });
    });
  });
}

function extractJson<T>(raw: string): T | undefined {
  // `claude -p --output-format json` wraps the reply; the model's own JSON may also
  // arrive fenced. Try the envelope first, then the first balanced object.
  try {
    const env = JSON.parse(raw);
    const inner = typeof env?.result === 'string' ? env.result : undefined;
    if (inner) {
      const m = inner.match(/\{[\s\S]*\}/);
      if (m) return JSON.parse(m[0]) as T;
    }
    if (env && typeof env === 'object' && !('result' in env)) return env as T;
  } catch {
    /* fall through */
  }
  const m = raw.match(/\{[\s\S]*\}/);
  if (m) {
    try {
      return JSON.parse(m[0]) as T;
    } catch {
      /* ignore */
    }
  }
  return undefined;
}

// ─── triage ──────────────────────────────────────────────────────────────────

export interface TriageVerdict {
  isPhish: boolean;
  confidence: 'low' | 'medium' | 'high';
  reasoning: string;
  payloadHosts: string[];
  lureStrings: string[];
  impersonates?: string;
  suggestedScopeQuery?: string;
}

const TRIAGE_PROMPT = (headers: string, body: string) => `
You are triaging one email for a K-12 school district's incident response console.

Reply with ONLY a JSON object, no prose, matching:
{"isPhish":bool,"confidence":"low"|"medium"|"high","reasoning":"one sentence",
 "payloadHosts":["host"],"lureStrings":["distinctive phrase"],
 "impersonates":"brand or person, omit if none",
 "suggestedScopeQuery":"a Gmail search that finds siblings of this message"}

Rules that matter here:
- SPF/DKIM/DMARC passing means NOTHING. Every confirmed attack against this district
  came from a genuinely compromised, fully authenticated partner-district account.
- Decode redirect wrappers (google.com/url?q=, click-trackers) and report the FINAL
  host in payloadHosts, not the wrapper.
- suggestedScopeQuery must NOT scope on sender alone — a sender-only sweep deletes a
  partner's legitimate mail. Prefer a distinctive lure phrase, optionally with subject.
- Gmail search cannot reliably match a bare domain inside a URL, so do not build
  suggestedScopeQuery out of a payload host.

HEADERS:
${headers}

BODY:
${body.slice(0, 6000)}
`.trim();

export function triageMessage(
  settings: AiSettings,
  headers: string,
  body: string
): Promise<AiResult<TriageVerdict>> {
  return serialise(async () => {
    const r = await invoke(settings, TRIAGE_PROMPT(headers, body));
    if (r.status !== 'ok') return { status: r.status, error: r.error, raw: r.raw };
    const data = extractJson<TriageVerdict>(r.raw ?? '');
    return data
      ? { status: 'ok' as const, data, raw: r.raw }
      : { status: 'bad_output' as const, raw: r.raw };
  });
}

// ─── advisory drafting ───────────────────────────────────────────────────────

export function draftAdvisory(
  settings: AiSettings,
  facts: string
): Promise<AiResult<string>> {
  const prompt = `
Draft a short peer advisory for a school-technology peer mailing list about
an active phishing campaign. Plain text, no preamble. Lead with what it looks like,
then indicators, then what a peer should run to check their own tenant.
State plainly that the sending accounts are legitimate compromised district mailboxes
and that SPF/DKIM/DMARC all pass, because that is the part peers get wrong.

FACTS:
${facts}
`.trim();

  return serialise(async () => {
    const r = await invoke(settings, prompt);
    if (r.status !== 'ok') return r;
    try {
      const env = JSON.parse(r.raw ?? '');
      if (typeof env?.result === 'string') return { status: 'ok', data: env.result };
    } catch {
      /* not an envelope */
    }
    return { status: 'ok', data: r.raw };
  });
}

/** Cheap liveness probe for the Settings page. */
export async function aiHealth(settings: AiSettings): Promise<AiResult<string>> {
  if (!settings.enabled) return { status: 'disabled' };
  const r = await serialise(() =>
    invoke({ ...settings, timeoutSeconds: 30 }, 'Reply with exactly: OK')
  );
  return r;
}

/**
 * Turn a stored report body into what Claude should read: the message as a person sees
 * it, followed by every link Warden extracted.
 *
 * WHY: the prompt keeps the first 6,000 characters of the body. Sent as raw HTML, a
 * phishing kit's inline CSS — `font-variant-numeric: normal; font-kerning: auto; …` on
 * every element — used up the whole budget before the call-to-action. On 2026-09-30
 * Claude correctly said it "was cut off before any link" and returned no payload host
 * for a message whose entire point was its Open button.
 *
 * Links go FIRST, because they are the evidence and they are short. They come from the
 * ingest's extractor, which has already unwrapped redirect wrappers, so they are better
 * than anything Claude could pull out of the HTML itself.
 */
export function triageBody(bodyText: string, payloadUrls: string[]): string {
  const text = bodyText
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    // Keep link targets visible inline, so "Open" becomes "Open [https://…]".
    .replace(/<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, '$2 [$1]')
    .replace(/<br\s*\/?>|<\/(p|div|tr|h\d|li|table)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&rsquo;|&lsquo;/g, "'")
    .replace(/&bull;/g, '•')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n')
    .trim();

  const links = [...new Set(payloadUrls)].slice(0, 25);
  const head = links.length
    ? `LINKS EXTRACTED BY WARDEN (redirect wrappers already unwrapped):\n${links.map((l) => `- ${l}`).join('\n')}\n\nMESSAGE TEXT:\n`
    : 'MESSAGE TEXT:\n';
  return head + text;
}
