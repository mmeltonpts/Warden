/**
 * Staff sign-in verification. Run from the scheduler tick.
 *
 *   sudo -u warden npx tsx scripts/verify-signins.ts
 *
 * Two passes each run:
 *   SEND   — for new risky staff flags (a VPN or foreign sign-in Google flagged), email the
 *            person to ask whether it was them, unless they were asked about the same network
 *            recently. The subject carries a code and the email a fixed Message-ID.
 *   CHECK  — for emails already sent, when a re-check is due: read the reply mailbox for an
 *            answer, read whether the sent email is still in the person's inbox, and look for
 *            a new filter that hides mail. A reply of NO, a vanished/filtered email, or such a
 *            filter raises an alarm; a reply of YES lowers suspicion.
 *
 * Warden never suspends an account or resets a password. This produces a confirmed finding
 * for a person to act on.
 */
import { PrismaClient } from '@prisma/client';
import { getSettings, notifyRecipients } from '../src/lib/settings';
import { sendMail, sendMessage, render } from '../src/lib/mailer';
import { errText } from '../src/lib/errors';
import { lookupIp, netKey } from '../src/lib/rdap';
import {
  makeCode, qualifiesForVerify, parseReplyDecision, hiddenVerdict,
  checkSchedule, nextCheckDue, pastLastCheck, renderVerifyEmail, codeFromSubject
} from '../src/lib/verify';
import { messageLabels, findReplies, suspiciousFilters } from '../src/lib/gam-mailbox';

const prisma = new PrismaClient();

async function main(): Promise<string> {
  const s = await getSettings(prisma);
  const cfg = s.signinVerify;
  if (!cfg.enabled) return 'disabled';
  if (!s.mail.enabled) return 'skipped — email notifications are off';
  if (!cfg.replyMailbox) return 'skipped — no reply mailbox set';

  const schedule = checkSchedule(cfg.checkMinutes);
  const staffSuffix = `@${s.domains.staff.toLowerCase()}`;
  let sent = 0;
  let denied = 0;
  let hidden = 0;
  let confirmed = 0;
  let expired = 0;

  // ── SEND ────────────────────────────────────────────────────────────────────
  const flags = await prisma.wardenRiskFlag.findMany({
    where: { state: 'NEW', score: { gte: cfg.minScore }, mailbox: { endsWith: staffSuffix } },
    orderBy: { ts: 'desc' },
    take: 100
  });

  for (const f of flags) {
    let reasons: string[] = [];
    try { reasons = JSON.parse(f.reasons) as string[]; } catch { reasons = []; }
    if (!qualifiesForVerify({ score: f.score, reasons }, { minScore: cfg.minScore, onlyVpnOrForeign: cfg.onlyVpnOrForeign })) continue;

    // Already handled this exact sign-in?
    if (await prisma.wardenSignInVerify.findFirst({ where: { mailbox: f.mailbox, signInTs: f.ts } })) continue;

    // Cooldown: same person, same network, asked recently.
    let key: string | null = null;
    try { key = f.ip ? netKey(f.ip) : null; } catch { key = null; }
    if (key) {
      const since = new Date(Date.now() - cfg.cooldownDays * 86400_000);
      const recent = await prisma.wardenSignInVerify.findFirst({
        where: { mailbox: f.mailbox, sentAt: { gte: since }, ip: { not: null } }
      });
      if (recent?.ip) {
        let rk: string | null = null;
        try { rk = netKey(recent.ip); } catch { rk = null; }
        if (rk === key) continue;
      }
    }

    const info = f.ip ? await lookupIp(prisma, f.ip, { timeoutMs: 8000 }).catch(() => null) : null;
    const org = info?.org || info?.name || 'an unrecognised network';
    const code = makeCode();
    const fromDomain = (s.mail.from.split('@')[1] || s.domains.staff).trim();
    const rfcMessageId = `warden-${code.toLowerCase()}@${fromDomain}`;
    const displayName = f.mailbox.split('@')[0].replace(/\./g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
    const when = f.ts.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const where = `${org}${f.geo ? ` (${f.geo})` : ''}`;

    const email = renderVerifyEmail(
      { subject: cfg.subject, body: cfg.body },
      { displayName, code, when, where, replyMailbox: cfg.replyMailbox, helpdesk: cfg.helpdesk }
    );

    const res = await sendMail(s.mail, [f.mailbox], email.subject, email.text, {
      throttleKey: `sv-${code}`,
      messageId: rfcMessageId,
      replyTo: cfg.replyMailbox
    });

    await prisma.wardenSignInVerify.create({
      data: {
        mailbox: f.mailbox,
        signInTs: f.ts,
        ip: f.ip,
        geo: f.geo,
        netOrg: org,
        score: f.score,
        riskFlagId: f.id,
        code,
        rfcMessageId,
        state: res.status === 'sent' ? 'SENT' : 'ERROR',
        notes: res.status === 'sent' ? null : `send ${res.status}${res.error ? `: ${res.error}` : ''}`
      }
    });
    if (res.status === 'sent') sent++;
  }

  // ── CHECK ─────────────────────────────────────────────────────────────────────
  const open = await prisma.wardenSignInVerify.findMany({ where: { state: 'SENT' }, orderBy: { sentAt: 'asc' }, take: 200 });
  const now = new Date();

  for (const v of open) {
    if (!nextCheckDue(v.sentAt, schedule, v.lastCheckedAt, now)) {
      if (pastLastCheck(v.sentAt, schedule, now)) {
        await prisma.wardenSignInVerify.update({ where: { id: v.id }, data: { state: 'EXPIRED', closedAt: now } });
        expired++;
      }
      continue;
    }

    const checks: Array<{ at: string; label: string; detail: string }> = (() => {
      try { return v.checks ? JSON.parse(v.checks) : []; } catch { return []; }
    })();
    const addCheck = (label: string, detail: string) => checks.push({ at: now.toISOString(), label, detail });

    let decided: 'CONFIRMED_YES' | 'DENIED' | 'HIDDEN' | null = null;
    let replyExcerpt: string | null = v.replyExcerpt;
    let filterFound: string | null = v.filterFound;

    // 1. A reply from the person.
    try {
      const replies = await findReplies(s.gamPath, cfg.replyMailbox, v.code);
      const fromUser = replies.filter((r) => r.from.toLowerCase().includes(v.mailbox.toLowerCase()) || codeFromSubject(r.subject) === v.code);
      const pick = (fromUser[0] ?? replies[0]);
      if (pick) {
        const decision = parseReplyDecision(pick.body);
        replyExcerpt = pick.body.replace(/\s+/g, ' ').trim().slice(0, 300);
        if (decision === 'no') { decided = 'DENIED'; addCheck('reply', 'the person replied that it was NOT them'); }
        else if (decision === 'yes') { decided = 'CONFIRMED_YES'; addCheck('reply', 'the person replied that it was them'); }
        else addCheck('reply', 'a reply arrived but did not clearly say yes or no');
      }
    } catch (e) {
      addCheck('reply', `could not read the reply mailbox: ${errText(e)}`);
    }

    // 2. What happened to the sent email. Only when not already decided by a reply.
    if (!decided && v.rfcMessageId) {
      try {
        const labels = await messageLabels(s.gamPath, v.mailbox, v.rfcMessageId);
        const verdict = hiddenVerdict(labels);
        addCheck('mailbox', verdict.detail);
        if (verdict.hidden) decided = 'HIDDEN';
      } catch (e) {
        addCheck('mailbox', `could not read the mailbox: ${errText(e)}`);
      }
    }

    // 3. A filter that hides security mail — flagged whatever the above said.
    try {
      const filters = await suspiciousFilters(s.gamPath, v.mailbox);
      if (filters.length) {
        filterFound = filters.join(' ; ').slice(0, 500);
        addCheck('filter', `a mail filter that hides security mail: ${filterFound}`);
        if (!decided) decided = 'HIDDEN';
      }
    } catch (e) {
      addCheck('filter', `could not list filters: ${errText(e)}`);
    }

    const closing = decided ?? (pastLastCheck(v.sentAt, schedule, now) ? 'EXPIRED' : null);
    await prisma.wardenSignInVerify.update({
      where: { id: v.id },
      data: {
        lastCheckedAt: now,
        checks: JSON.stringify(checks.slice(-20)),
        replyExcerpt,
        filterFound,
        ...(closing ? { state: closing, closedAt: now } : {})
      }
    });

    if (decided === 'DENIED') denied++;
    else if (decided === 'HIDDEN') hidden++;
    else if (decided === 'CONFIRMED_YES') confirmed++;
    else if (closing === 'EXPIRED') expired++;

    // Alarm + escalate the linked flag for the decisive outcomes.
    if (decided === 'DENIED' || decided === 'HIDDEN') {
      if (v.riskFlagId) {
        await prisma.wardenRiskFlag.update({ where: { id: v.riskFlagId }, data: { state: 'INVESTIGATING' } }).catch(() => undefined);
      }
      const why = decided === 'DENIED'
        ? 'The person replied that this sign-in was NOT them.'
        : (filterFound ? 'A mail filter that hides security mail was found on the account.' : 'The verification email was deleted or filtered out of the inbox within minutes — the fingerprint of an attacker rule.');
      const msg = render({
        title: `Account takeover likely: ${v.mailbox}`,
        lede: why,
        blocks: [
          { rows: [
            ['Mailbox', v.mailbox],
            ['Sign-in', v.signInTs.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'],
            ['Network', `${v.netOrg ?? '?'}${v.geo ? ` (${v.geo})` : ''}`],
            ['Verification', decided]
          ] },
          { heading: 'What to do now', items: [
            { title: 'Reset the password and revoke sessions', severity: 'critical' },
            { title: 'Run an account check (filters, forwarding, delegates)', severity: 'high' },
            { title: 'Check what the account sent or did since the sign-in', severity: 'high' }
          ] },
          ...(replyExcerpt ? [{ heading: 'Their reply', lines: [replyExcerpt] }] : [])
        ],
        cta: { label: 'Open sign-in risk', href: `${s.consoleUrl}/risk` },
        baseUrl: s.consoleUrl
      });
      const to = await notifyRecipients(prisma);
      await sendMessage(s.mail, to, { subject: `[Warden] Account takeover likely — ${v.mailbox}`, ...msg }, { throttleKey: `sv-alarm-${v.id}` })
        .catch((e) => console.error('verify alarm mail failed:', errText(e)));
    }
  }

  return `sent ${sent}, confirmed ${confirmed}, DENIED ${denied}, HIDDEN ${hidden}, expired ${expired}`;
}

if (require.main === module) {
  main().then((r) => console.log(r)).catch((e) => { console.error(errText(e)); process.exitCode = 1; }).finally(() => prisma.$disconnect());
}

export { main as runVerifySignins };
