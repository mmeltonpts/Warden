/**
 * Connection tests offered by the setup wizard. Each returns plain pass/fail lines with
 * the real error text, because "it didn't work" during setup is only useful if it says
 * which step failed and why.
 */
import { execFile } from 'node:child_process';
import type { PrismaClient } from '@prisma/client';
import { errText } from './errors';
import { getSettings } from './settings';
import { sendMail } from './mailer';
import { falconHealth } from './crowdstrike';
import { kb4Health } from './knowbe4';
import { aiHealth } from './ai';
import { HOST_CMD } from './runtime';

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  link?: string;
}

function run(bin: string, args: string[], timeoutMs = 90_000): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    // execFile buffers stdout AND stderr, so neither pipe can fill and block GAM.
    execFile(bin, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const out = `${stdout ?? ''}\n${stderr ?? ''}`.trim();
      if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
        resolve({ code: null, out: `cannot execute ${bin} — not found` });
        return;
      }
      const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? Number((err as { code?: number }).code) : -1) : 0;
      resolve({ code, out: err && !out ? errText(err) : out });
    });
  });
}

const firstLines = (s: string, n = 4) => s.split('\n').map((l) => l.trim()).filter(Boolean).slice(0, n).join(' · ');

/**
 * GAM, in the order setup has to happen: the binary runs, admin API access works, and the
 * service account's domain-wide delegation covers what Warden needs, checked against a
 * real mailbox.
 */
export async function gamChecks(prisma: PrismaClient, testMailbox: string): Promise<Check[]> {
  const s = await getSettings(prisma);
  const out: Check[] = [];

  const v = await run(s.gamPath, ['version'], 30_000);
  out.push({ name: 'GAM runs', ok: v.code === 0, detail: firstLines(v.out, 2) || 'no output' });
  if (v.code !== 0) return out;

  const d = await run(s.gamPath, ['info', 'domain']);
  const primary = d.out.match(/Primary Domain:\s*(\S+)/i)?.[1];
  out.push({
    name: 'Admin API access (gam oauth create)',
    ok: d.code === 0,
    detail: d.code === 0 ? `primary domain ${primary ?? 'unknown'}` : firstLines(d.out)
  });
  if (d.code === 0 && primary && s.domains.staff && primary.toLowerCase() !== s.domains.staff.toLowerCase()) {
    out.push({
      name: 'Staff domain matches the tenant',
      ok: false,
      detail: `GAM is authorised for ${primary} but the staff domain is set to ${s.domains.staff}. Fine if ${s.domains.staff} is a secondary domain of the same tenant; otherwise fix one of them.`
    });
  }

  if (!testMailbox) {
    out.push({ name: 'Domain-wide delegation', ok: false, detail: 'no mailbox to test against — set the staff domain first' });
    return out;
  }
  const c = await run(s.gamPath, ['user', testMailbox, 'check', 'serviceaccount'], 120_000);
  const link = c.out.match(/https:\/\/admin\.google\.com\/ac\/owl\/domainwidedelegation\S*/)?.[0];
  const failed = c.code !== 0 || /\bFAIL\b/.test(c.out);
  out.push({
    name: `Domain-wide delegation (checked against ${testMailbox})`,
    ok: !failed,
    detail: failed
      ? 'Some scopes are not authorised. Open the link, authorise exactly the scopes listed, wait a minute, and test again.'
      : 'all required scopes authorised',
    link: failed ? link : undefined
  });
  return out;
}

export async function mailCheck(prisma: PrismaClient, to: string): Promise<Check[]> {
  const s = await getSettings(prisma);
  const r = await sendMail(
    s.mail,
    [to],
    'Warden: test message',
    `This is a test from the Warden setup wizard. If you can read it, notifications work.\n\n${s.consoleUrl}`,
    { throttleKey: `setup-test-${Date.now()}` }
  );
  return [{
    name: `Test email to ${to}`,
    ok: r.status === 'sent',
    detail: r.status === 'sent' ? 'accepted by the relay — check the inbox (and spam)' : `${r.status}${r.error ? `: ${r.error}` : ''}`
  }];
}

export async function falconChecks(prisma: PrismaClient): Promise<Check[]> {
  const h = await falconHealth((await getSettings(prisma)).crowdstrike);
  return [h.token, ...h.scopes].map((c) => ({ name: c.scope, ok: c.ok, detail: c.detail }));
}

export async function kb4Checks(prisma: PrismaClient): Promise<Check[]> {
  const h = await kb4Health((await getSettings(prisma)).knowbe4);
  const line = (name: string, r: { status: string; error?: string; httpStatus?: number }): Check => ({
    name,
    ok: r.status === 'ok',
    detail: r.status === 'ok' ? 'reachable' : `${r.status}${r.httpStatus ? ` (HTTP ${r.httpStatus})` : ''}${r.error ? `: ${r.error}` : ''}`
  });
  const out = [line('Reporting API', h.reporting), line('User Events API', h.userEvents)];
  if (h.eventTypes?.missing.length) {
    out.push({ name: 'Event types', ok: false, detail: `not defined in KnowBe4 yet: ${h.eventTypes.missing.join(', ')}` });
  }
  return out;
}

export async function claudeChecks(prisma: PrismaClient): Promise<Check[]> {
  const r = await aiHealth((await getSettings(prisma)).ai);
  return [{
    name: 'Claude CLI',
    ok: r.status === 'ok',
    detail: r.status === 'ok'
      ? 'signed in and answering'
      : `${r.status}${r.error ? `: ${r.error}` : ''} — sign in with: ${HOST_CMD.claudeLogin.split('\n')[0]}   then /login`
  }];
}
