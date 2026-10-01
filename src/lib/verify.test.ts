import { describe, it, expect } from 'vitest';
import {
  codeFromSubject, qualifiesForVerify, parseReplyDecision, hiddenVerdict,
  checkSchedule, nextCheckDue, pastLastCheck, renderVerifyEmail,
  parseBuildingMap, buildingAdminFor, duringSchoolHours
} from './verify';

describe('staff verification', () => {
  it('pulls the code back out of a reply subject', () => {
    expect(codeFromSubject('Re: Security check [SV-7bq2kf1a]')).toBe('SV-7BQ2KF1A');
    expect(codeFromSubject('no code here')).toBeNull();
  });

  it('only verifies VPN/foreign flags at or above the score', () => {
    const vpn = { score: 55, reasons: ['Consumer VPN or privacy relay (Cloudflare)'] };
    expect(qualifiesForVerify(vpn, { minScore: 50, onlyVpnOrForeign: true })).toBe(true);
    expect(qualifiesForVerify({ ...vpn, score: 40 }, { minScore: 50, onlyVpnOrForeign: true })).toBe(false);
    const onNet = { score: 60, reasons: ['On the district network'] };
    expect(qualifiesForVerify(onNet, { minScore: 50, onlyVpnOrForeign: true })).toBe(false);
    expect(qualifiesForVerify(onNet, { minScore: 50, onlyVpnOrForeign: false })).toBe(true);
  });

  it('reads a reply, and a denial always wins', () => {
    expect(parseReplyDecision('Yes that was me, thanks')).toBe('yes');
    expect(parseReplyDecision('No! I was not in Wisconsin')).toBe('no');
    expect(parseReplyDecision('')).toBeNull();
    // Only the text above the quoted original counts.
    expect(parseReplyDecision('no\n\nOn Tue someone wrote:\n> yes it was me')).toBe('no');
  });

  it('treats a vanished or filtered email as hidden', () => {
    expect(hiddenVerdict(null).hidden).toBe(true);
    expect(hiddenVerdict(['TRASH']).hidden).toBe(true);
    expect(hiddenVerdict(['SPAM']).hidden).toBe(true);
    expect(hiddenVerdict(['IMPORTANT']).hidden).toBe(true); // archived out of inbox
    expect(hiddenVerdict(['INBOX', 'UNREAD']).hidden).toBe(false);
    expect(hiddenVerdict(['INBOX']).detail).toMatch(/read/);
  });

  it('schedules re-checks and expiry', () => {
    const sent = new Date('2026-10-02T12:00:00Z');
    expect(checkSchedule('2, 10 ,30')).toEqual([2, 10, 30]);
    // 3 min in, nothing checked yet: the 2-min check is due.
    expect(nextCheckDue(sent, [2, 10, 30], null, new Date('2026-10-02T12:03:00Z'))).toBe(true);
    // 3 min in, already did the 2-min check: nothing new due.
    expect(nextCheckDue(sent, [2, 10, 30], new Date('2026-10-02T12:02:30Z'), new Date('2026-10-02T12:03:00Z'))).toBe(false);
    // 11 min in, last check was the 2-min one: the 10-min check is due.
    expect(nextCheckDue(sent, [2, 10, 30], new Date('2026-10-02T12:02:30Z'), new Date('2026-10-02T12:11:00Z'))).toBe(true);
    expect(pastLastCheck(sent, [2, 10, 30], new Date('2026-10-02T12:31:00Z'))).toBe(true);
    expect(pastLastCheck(sent, [2, 10, 30], new Date('2026-10-02T12:20:00Z'))).toBe(false);
  });

  it('renders the email and forces the code into the subject', () => {
    const { subject, text } = renderVerifyEmail(
      { subject: 'Security check: did you just sign in?', body: 'Hi {name}, was it you at {when} from {where}? Reply to {reply}.' },
      { displayName: 'Alex', code: 'SV-aabbccdd', when: 'today 13:26', where: 'a VPN (US-WI)', replyMailbox: 'verify@x.org', helpdesk: 'x4000' }
    );
    expect(subject).toContain('[SV-aabbccdd]');
    expect(text).toBe('Hi Alex, was it you at today 13:26 from a VPN (US-WI)? Reply to verify@x.org.');
    // A template that already has the code is left as-is.
    expect(renderVerifyEmail({ subject: 'Check [SV-11223344]', body: '' }, { displayName: '', code: 'SV-11223344', when: '', where: '', replyMailbox: '', helpdesk: '' }).subject).toBe('Check [SV-11223344]');
  });
});

describe('student VPN notice routing', () => {
  const map = parseBuildingMap(`
    # building defaults
    /Student Accounts/PHS = phs.admin@example.org
    /Student Accounts/IMS = ims.admin@example.org
    /Student Accounts/PHS/12 = phs.seniors@example.org
  `);

  it('routes to the longest matching OU prefix', () => {
    expect(buildingAdminFor('/Student Accounts/PHS/11', map)).toBe('phs.admin@example.org');
    expect(buildingAdminFor('/Student Accounts/PHS/12', map)).toBe('phs.seniors@example.org');
    expect(buildingAdminFor('/Student Accounts/IMS/08', map)).toBe('ims.admin@example.org');
    expect(buildingAdminFor('/Staff', map)).toBeNull();
  });

  it('does not match a building that merely shares a name prefix', () => {
    expect(buildingAdminFor('/Student Accounts/PHSX/11', map)).toBeNull();
  });

  it('tells school hours from evening, on school days only', () => {
    const opts = { offsetMinutes: -300, days: [1, 2, 3, 4, 5], window: '07:30-15:00' };
    expect(duringSchoolHours(new Date('2026-10-02T15:00:00Z'), opts)).toBe(true);  // Fri 10:00 local
    expect(duringSchoolHours(new Date('2026-10-02T02:00:00Z'), opts)).toBe(false); // Thu 21:00 local
    expect(duringSchoolHours(new Date('2026-10-03T16:00:00Z'), opts)).toBe(false); // Sat
  });
});
