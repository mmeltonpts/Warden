/**
 * Notifications via SMTP relay.
 *
 * No credentials by default. Google's relay authenticates by SOURCE IP, configured in
 * Admin console -> Apps -> Google Workspace -> Gmail -> Routing -> SMTP relay service.
 *
 * IMPORTANT, and easy to get wrong: the IP the relay sees is this host's PUBLIC egress,
 * not its private address. Allowlisting the private address silently does nothing.
 *
 * Equally easy to get wrong, and it cost a day: the EHLO name must be a fully-qualified
 * domain. A host named `box` with no domain makes nodemailer fall back to an address
 * literal and send `EHLO [127.0.0.1]`, which Google rejects with
 * `421-4.7.0 Try again later, closing connection. (EHLO)` — an error that reads exactly
 * like an unauthorised source IP and sends you to the wrong place entirely.
 *
 * Nothing here is on a critical path. A relay outage must never stop a sweep: every send
 * is best-effort and failures are returned, never thrown.
 *
 * ON FORMATTING: every message goes out as multipart/alternative — a real plain-text part
 * and an HTML part built from the same blocks, so there is one source of truth and the
 * text version is never an afterthought. Layout is tables with inline styles because that
 * is what mail clients actually render. No external images, no web fonts, no tracking.
 *
 * ON LINKS: a payload URL is NEVER a clickable anchor in a notification. These messages
 * are about hostile mail, they land in a human's inbox, and clients prefetch. Hostile URLs
 * are defanged to `hxxps://evil[.]example` in both parts.
 */
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { errText } from './errors';

export interface MailSettings {
  enabled: boolean;
  host: string;
  port: number;
  from: string;
  /** MUST be a fully-qualified domain name. See the note at the top of this file. */
  ehloName: string;
  /**
   * Who gets notified, by role. Additive, and combined with `recipients`.
   *
   * Roles rather than a typed list so that adding somebody to the console adds them to the
   * paging list — a notification list maintained by hand goes stale the first time
   * somebody changes jobs, and nobody notices until an incident.
   */
  notifyAdmins: boolean;
  notifyResponders: boolean;
  notifyAnalysts: boolean;
  /** Extra addresses, comma-separated. Added to whichever roles are ticked. */
  recipients: string;
  /** Suppress repeat notifications for the same subject within this window. */
  throttleMinutes: number;
}

export const MAIL_DEFAULTS: MailSettings = {
  enabled: false,
  host: 'smtp-relay.gmail.com',
  port: 587,
  from: '',
  ehloName: '',
  notifyAdmins: true,
  notifyResponders: true,
  notifyAnalysts: false,
  recipients: '',
  throttleMinutes: 30
};

export type MailStatus = 'sent' | 'disabled' | 'no_recipients' | 'throttled' | 'error';

export interface MailResult {
  status: MailStatus;
  error?: string;
  recipients?: string[];
}

export interface Message {
  subject: string;
  text: string;
  html: string;
}

type G = typeof globalThis & { wardenMailSeen?: Map<string, number> };
const g = globalThis as G;

/** Pinned to globalThis: route handlers and the worker are different module instances. */
function seen(): Map<string, number> {
  if (!g.wardenMailSeen) g.wardenMailSeen = new Map();
  return g.wardenMailSeen;
}

function transport(s: MailSettings): Transporter {
  return nodemailer.createTransport({
    host: s.host,
    port: s.port,
    // Only pass a name when it is actually qualified — a bare hostname is no better than
    // the fallback, and silently sending a broken one is how this hid for a day.
    ...(s.ehloName && s.ehloName.includes('.') ? { name: s.ehloName } : {}),
    secure: false,
    requireTLS: true,
    // No auth block at all — IP-based relay. Empty credentials make nodemailer attempt
    // AUTH, and the relay then rejects the session.
    tls: { minVersion: 'TLSv1.2' },
    connectionTimeout: 15_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000
  });
}

export async function sendMail(
  s: MailSettings,
  to: string[],
  subject: string,
  text: string,
  opts: { throttleKey?: string; html?: string; messageId?: string; replyTo?: string } = {}
): Promise<MailResult> {
  if (!s.enabled) return { status: 'disabled' };
  const rcpt = to.map((x) => x.trim()).filter(Boolean);
  if (!rcpt.length) return { status: 'no_recipients' };

  const key = opts.throttleKey ?? subject;
  const last = seen().get(key) ?? 0;
  if (Date.now() - last < s.throttleMinutes * 60_000) return { status: 'throttled' };

  try {
    await transport(s).sendMail({
      from: s.from,
      to: rcpt.join(', '),
      subject,
      text,
      ...(opts.html ? { html: opts.html } : {}),
      // A fixed Message-ID lets a caller find this exact message again in the recipient's
      // mailbox (the sign-in verification reads its own labels back). nodemailer wants the
      // angle brackets; callers pass the bare id.
      ...(opts.messageId ? { messageId: opts.messageId.startsWith('<') ? opts.messageId : `<${opts.messageId}>` } : {}),
      ...(opts.replyTo ? { replyTo: opts.replyTo } : {}),
      headers: {
        // Keeps notifications out of anyone's vacation-responder loop, and marks them
        // machine-generated for any downstream filtering.
        'Auto-Submitted': 'auto-generated',
        'X-Auto-Response-Suppress': 'All',
        'X-Warden-Notification': '1'
      }
    });
    seen().set(key, Date.now());
    return { status: 'sent', recipients: rcpt };
  } catch (e) {
    return { status: 'error', error: errText(e) };
  }
}

/** Convenience: send a built Message without repeating subject/text/html at every call. */
export function sendMessage(
  s: MailSettings,
  to: string[],
  m: Message,
  opts: { throttleKey?: string } = {}
): Promise<MailResult> {
  return sendMail(s, to, m.subject, m.text, { ...opts, html: m.html });
}

// ─── rendering ───────────────────────────────────────────────────────────────

const C = {
  ink: '#16181d',
  muted: '#5b6472',
  line: '#dfe3ea',
  panel: '#f6f8fa',
  critical: '#b3261e',
  high: '#9a6700',
  ok: '#1a7f37',
  accent: '#1f4e9c'
};

export type Severity = 'critical' | 'high' | 'ok' | 'muted';

export interface Block {
  heading?: string;
  /** Free paragraphs. */
  lines?: string[];
  /** Label/value pairs, rendered as a table. */
  rows?: Array<[string, string]>;
  /** A list of findings. */
  items?: Array<{ title: string; meta?: string; detail?: string; severity?: Severity }>;
  /** Preformatted, monospace. Used for queries and defanged URLs. */
  pre?: string;
  /** Small print under the block. */
  note?: string;
}

const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/**
 * Render a URL inert.
 *
 * Notifications about hostile mail must not carry a live link to the payload. Mail clients
 * prefetch, preview and sometimes rewrite links, and the recipient is a human who has just
 * been told this is dangerous.
 */
export function defangUrl(u: string): string {
  return u.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

function sevColor(s?: Severity) {
  return s === 'critical' ? C.critical : s === 'high' ? C.high : s === 'ok' ? C.ok : C.muted;
}

export function render(o: {
  title: string;
  lede?: string;
  blocks: Block[];
  cta?: { label: string; href: string };
  baseUrl: string;
}): { text: string; html: string } {
  // ── text ───────────────────────────────────────────────────────────────────
  const t: string[] = [];
  if (o.lede) t.push(o.lede, '');
  for (const b of o.blocks) {
    if (b.heading) t.push(b.heading.toUpperCase(), '');
    for (const l of b.lines ?? []) t.push(l, '');
    if (b.rows?.length) {
      const w = Math.max(...b.rows.map(([k]) => k.length));
      for (const [k, v] of b.rows) t.push(`  ${k.padEnd(w)}  ${v}`);
      t.push('');
    }
    for (const it of b.items ?? []) {
      t.push(`  * ${it.title}`);
      if (it.meta) t.push(`      ${it.meta}`);
      if (it.detail) t.push(`      ${it.detail}`);
    }
    if (b.items?.length) t.push('');
    if (b.pre) t.push(b.pre.split('\n').map((l) => '  ' + l).join('\n'), '');
    if (b.note) t.push(b.note, '');
  }
  if (o.cta) t.push(`${o.cta.label}: ${o.cta.href}`, '');
  t.push('—', `Warden · ${o.baseUrl}`, 'Automated notification. Do not reply — this address is not monitored.');

  // ── html ───────────────────────────────────────────────────────────────────
  const h: string[] = [];
  for (const b of o.blocks) {
    h.push('<tr><td style="padding:0 28px;">');
    if (b.heading) {
      h.push(
        `<div style="margin:22px 0 8px;font:600 12px/1.4 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;` +
          `letter-spacing:.07em;text-transform:uppercase;color:${C.muted};">${esc(b.heading)}</div>`
      );
    }
    for (const l of b.lines ?? []) {
      h.push(
        `<p style="margin:0 0 12px;font:400 15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.ink};">${esc(l)}</p>`
      );
    }
    if (b.rows?.length) {
      h.push(
        `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:0 0 14px;">`
      );
      for (const [k, v] of b.rows) {
        h.push(
          `<tr>` +
            `<td style="padding:6px 12px 6px 0;vertical-align:top;white-space:nowrap;font:400 13px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.muted};">${esc(k)}</td>` +
            `<td style="padding:6px 0;vertical-align:top;font:400 13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:${C.ink};word-break:break-all;">${esc(v)}</td>` +
            `</tr>`
        );
      }
      h.push('</table>');
    }
    for (const it of b.items ?? []) {
      const col = sevColor(it.severity);
      h.push(
        `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:0 0 10px;">` +
          `<tr><td style="padding:10px 14px;background:${C.panel};border-left:3px solid ${col};border-radius:2px;">` +
          `<div style="font:600 14px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.ink};word-break:break-word;">${esc(it.title)}</div>` +
          (it.meta
            ? `<div style="margin-top:3px;font:400 12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:${C.muted};word-break:break-all;">${esc(it.meta)}</div>`
            : '') +
          (it.detail
            ? `<div style="margin-top:5px;font:400 13px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.ink};">${esc(it.detail)}</div>`
            : '') +
          `</td></tr></table>`
      );
    }
    if (b.pre) {
      h.push(
        `<pre style="margin:0 0 14px;padding:12px 14px;background:${C.panel};border:1px solid ${C.line};border-radius:3px;` +
          `font:400 12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:${C.ink};white-space:pre-wrap;word-break:break-all;">${esc(b.pre)}</pre>`
      );
    }
    if (b.note) {
      h.push(
        `<p style="margin:0 0 14px;font:400 12px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.muted};">${esc(b.note)}</p>`
      );
    }
    h.push('</td></tr>');
  }

  const cta = o.cta
    ? `<tr><td style="padding:6px 28px 4px;">` +
      `<a href="${esc(o.cta.href)}" style="display:inline-block;padding:9px 18px;background:${C.accent};color:#fff;` +
      `text-decoration:none;border-radius:3px;font:600 14px/1 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">${esc(o.cta.label)}</a>` +
      `</td></tr>`
    : '';

  const html =
    `<!doctype html><html><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="color-scheme" content="light only"><title>${esc(o.title)}</title></head>` +
    `<body style="margin:0;padding:0;background:#eef1f5;">` +
    `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;background:#eef1f5;">` +
    `<tr><td align="center" style="padding:22px 12px;">` +
    `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;max-width:640px;background:#fff;border:1px solid ${C.line};border-radius:5px;">` +
    `<tr><td style="padding:20px 28px 4px;border-bottom:1px solid ${C.line};">` +
    `<div style="font:700 11px/1 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;letter-spacing:.16em;color:${C.muted};">WARDEN</div>` +
    `<h1 style="margin:8px 0 14px;font:600 19px/1.35 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.ink};">${esc(o.title)}</h1>` +
    `</td></tr>` +
    (o.lede
      ? `<tr><td style="padding:16px 28px 0;"><p style="margin:0;font:400 15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.ink};">${esc(o.lede)}</p></td></tr>`
      : '') +
    h.join('') +
    cta +
    `<tr><td style="padding:18px 28px 22px;border-top:1px solid ${C.line};">` +
    `<p style="margin:0;font:400 12px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${C.muted};">` +
    `Warden · <a href="${esc(o.baseUrl)}" style="color:${C.accent};text-decoration:none;">${esc(o.baseUrl)}</a><br>` +
    `Automated notification. Do not reply — this address is not monitored.</p>` +
    `</td></tr></table></td></tr></table></body></html>`;

  return { text: t.join('\n'), html };
}

// ─── templates ───────────────────────────────────────────────────────────────

export function riskDigest(
  flags: Array<{ mailbox: string; score: number; ts: Date; reasons: string[]; ip?: string | null; geo?: string | null }>,
  baseUrl: string
): Message {
  const top = flags[0];
  const subject =
    flags.length === 1
      ? `Warden: risk flag ${top.score} — ${top.mailbox.split('@')[0]}`
      : `Warden: ${flags.length} sign-in risk flags (highest ${top.score})`;

  const { text, html } = render({
    title: flags.length === 1 ? 'Sign-in risk flag' : `${flags.length} sign-in risk flags`,
    lede: `The scheduled sign-in scan raised ${flags.length} flag${flags.length === 1 ? '' : 's'}.`,
    blocks: [
      {
        items: flags.map((f) => ({
          title: `${f.score}  ${f.mailbox}`,
          meta: [f.ts.toISOString().slice(0, 16).replace('T', ' ') + 'Z', f.ip, f.geo].filter(Boolean).join('  ·  '),
          detail: f.reasons.join(' · '),
          severity: f.score >= 70 ? ('critical' as const) : ('high' as const)
        }))
      },
      {
        note:
          'These are scored against each mailbox’s own learned normal, not a fixed rule. ' +
          'Carrier geolocation is not travel: mobile IPv6 can geolocate hundreds of miles from ' +
          'the handset. Confirm with the person before acting.'
      }
    ],
    cta: { label: 'Open risk queue', href: `${baseUrl}/risk` },
    baseUrl
  });
  return { subject, text, html };
}

/** New staff phish reports found by an ingest run. */
export function reportDigest(
  o: {
    created: number;
    campaigns: Array<{ subject: string; sender: string | null; count: number; hosts: string[] }>;
    suppressed: number;
  },
  baseUrl: string
): Message {
  const worst = o.campaigns[0];
  const subject =
    o.campaigns.length === 1 && worst
      ? `Warden: ${o.created} new phish report${o.created === 1 ? '' : 's'} — ${worst.subject.slice(0, 60)}`
      : `Warden: ${o.created} new phish reports across ${o.campaigns.length} campaigns`;

  const { text, html } = render({
    title: `${o.created} new phish report${o.created === 1 ? '' : 's'}`,
    lede:
      `Staff reported ${o.created} message${o.created === 1 ? '' : 's'} since the last run` +
      (o.suppressed ? `, and ${o.suppressed} more matched the known-good list and were filed automatically.` : '.'),
    blocks: [
      {
        heading: 'Grouped by campaign',
        items: o.campaigns.map((c) => ({
          title: `${c.count} ×  ${c.subject}`,
          meta: [c.sender, c.hosts.map(defangUrl).join(', ')].filter(Boolean).join('  ·  '),
          severity: c.count >= 5 ? ('critical' as const) : ('high' as const)
        }))
      },
      {
        note:
          'A report is a person saying “this looks wrong”, not a confirmed finding. ' +
          'Payload hosts are shown defanged and are deliberately not clickable.'
      }
    ],
    cta: { label: 'Triage reports', href: `${baseUrl}/reports` },
    baseUrl
  });
  return { subject, text, html };
}

/** New Alert Center alerts worth waking someone for. */
export function alertDigest(
  o: {
    items: Array<{ type: string; who: string; detail: string; severity: Severity }>;
    autoFiled: number;
    total: number;
  },
  baseUrl: string
): Message {
  const kinds = [...new Set(o.items.map((i) => i.type))];
  const subject =
    o.items.length === 1
      ? `Warden: ${o.items[0].type} — ${o.items[0].who}`
      : `Warden: ${o.items.length} new alerts (${kinds.slice(0, 2).join(', ')}${kinds.length > 2 ? '…' : ''})`;

  const { text, html } = render({
    title: `${o.items.length} new alert${o.items.length === 1 ? '' : 's'} need a look`,
    lede:
      `Google raised ${o.total} alert${o.total === 1 ? '' : 's'} since the last run. ` +
      (o.autoFiled
        ? `${o.autoFiled} were sign-ins from known residential or carrier networks and were filed automatically; the rest are below.`
        : 'These are the ones that were not filed automatically.'),
    blocks: [
      {
        items: o.items.map((i) => ({
          title: `${i.type} — ${i.who}`,
          detail: i.detail,
          severity: i.severity
        }))
      },
      {
        note:
          'Gmail’s own “Report phishing” forwards nothing to anybody — it raises an alert ' +
          'and that is the entire record, which is why these never reach a report mailbox.'
      }
    ],
    cta: { label: 'Open alerts', href: `${baseUrl}/alerts` },
    baseUrl
  });
  return { subject, text, html };
}

export function sweepNotice(
  o: { operator: string; query: string; trashed: number; mailboxes: number; domain: string },
  baseUrl: string
): Message {
  const { text, html } = render({
    title: `Sweep trashed ${o.trashed} messages`,
    lede: `${o.operator} ran a sweep against ${o.domain}.`,
    blocks: [
      {
        rows: [
          ['Query', o.query],
          ['Domain', o.domain],
          ['Trashed', `${o.trashed} messages across ${o.mailboxes} mailboxes`]
        ]
      },
      {
        note:
          'Messages went to Trash, not permanent delete — recoverable, and kept as evidence. ' +
          'A verification job was queued automatically; verification is part of the operation, ' +
          'not a follow-up someone might skip.'
      }
    ],
    cta: { label: 'Open jobs', href: `${baseUrl}/jobs` },
    baseUrl
  });
  return { subject: `Warden: sweep trashed ${o.trashed} messages (${o.domain})`, text, html };
}

export function verifyAlert(
  o: { query: string; survivors: number; domain: string; inconclusive?: boolean },
  baseUrl: string
): Message {
  // An inconclusive verify must be as loud as a failed one. Silence from this mailer is
  // the signal that a sweep was confirmed clean, so a run that could not check anything
  // cannot be allowed to look the same as one that checked and found nothing.
  if (o.inconclusive) {
    const { text, html } = render({
      title: 'A sweep could NOT be verified',
      lede: 'Post-sweep verification did not complete, so nothing about this sweep is confirmed.',
      blocks: [
        { rows: [['Query', o.query], ['Domain', o.domain], ['Rows parsed before it stopped', String(o.survivors)]] },
        {
          note:
            'This is not a clean result and must not be read as one. GAM exited early or was ' +
            'killed at the scan timeout, which produces an empty result indistinguishable from ' +
            '"nothing survived". Re-run the verify before closing the incident. A bulk sweep ' +
            'once reported success while a copy sat unlabelled outside the Inbox.'
        }
      ],
      cta: { label: 'Open jobs', href: `${baseUrl}/jobs` },
      baseUrl
    });
    return { subject: `Warden: sweep NOT VERIFIED — check did not complete (${o.domain})`, text, html };
  }

  const { text, html } = render({
    title: `${o.survivors} messages survived a sweep`,
    lede: 'Post-sweep verification found copies still present outside Trash.',
    blocks: [
      { rows: [['Query', o.query], ['Domain', o.domain], ['Remaining', String(o.survivors)]] },
      {
        note:
          'This is why every sweep verifies. A bulk sweep once reported success while a copy ' +
          'sat unlabelled outside the Inbox. Investigate before closing the incident.'
      }
    ],
    cta: { label: 'Open jobs', href: `${baseUrl}/jobs` },
    baseUrl
  });
  return { subject: `Warden: ${o.survivors} messages SURVIVED a sweep (${o.domain})`, text, html };
}

export function scanFailure(error: string, baseUrl: string): Message {
  const { text, html } = render({
    title: 'Scheduled scan failed',
    lede: 'The scheduled sign-in risk scan did not complete.',
    blocks: [
      { pre: error },
      {
        note:
          'No baselines were updated and no flags were raised for this window. If GAM ' +
          'authentication has expired, every scope, sweep and ingest is affected too.'
      }
    ],
    cta: { label: 'Open console', href: baseUrl },
    baseUrl
  });
  return { subject: 'Warden: scheduled sign-in scan FAILED', text, html };
}

export function welcomeNotice(
  o: { email: string; displayName: string; role: string; invitedBy: string },
  baseUrl: string
): Message {
  const ROLE: Record<string, string> = {
    ANALYST: 'Analyst — read only. You can scope, triage and review, but not sweep mail.',
    RESPONDER: 'Responder — you can execute sweeps, after previewing exactly what they touch.',
    ADMIN: 'Admin — full access, including settings and user management.'
  };
  const { text, html } = render({
    title: 'Your Warden account',
    lede: `${o.invitedBy} created a Warden account for you.`,
    blocks: [
      { rows: [['Console', baseUrl], ['Sign in as', o.email], ['Role', ROLE[o.role] ?? o.role]] },
      {
        lines: [
          `Your password is not in this email. ${o.invitedBy} will pass it to you another way — ` +
            'this console can delete mail across every mailbox in the district, so its credentials ' +
            'do not travel by email. Change it once you have signed in.'
        ],
        note: `If you were not expecting this, contact ${o.invitedBy} directly and do not sign in.`
      }
    ],
    cta: { label: 'Open Warden', href: baseUrl },
    baseUrl
  });
  return { subject: 'Your Warden account', text, html };
}

export function passwordResetNotice(o: { email: string; resetBy: string }, baseUrl: string): Message {
  const { text, html } = render({
    title: 'Your Warden password was reset',
    lede: `${o.resetBy} reset the password on your Warden account (${o.email}).`,
    blocks: [
      { rows: [['Console', baseUrl]] },
      {
        lines: [
          `The new password is not in this email; ${o.resetBy} will pass it to you another way. ` +
            'Any existing sessions were signed out.'
        ],
        note: `If you did not expect this, contact ${o.resetBy}. A reset you did not request is worth asking about.`
      }
    ],
    cta: { label: 'Open Warden', href: baseUrl },
    baseUrl
  });
  return { subject: 'Your Warden password was reset', text, html };
}
