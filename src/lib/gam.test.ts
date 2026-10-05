import { describe, it, expect } from 'vitest';
import {
  verifyQuery,
  protectiveSuffix,
  flagsFromAccountCheck,
  DEFAULT_PROTECTED_SUBJECTS,
  gamCompleted,
  assertSweepSafe,
  reachedEnd,
  trashIdsArgs,
  labelIdsArgs,
  gamPathReason,
  parseRemovableItems,
  type GamSettings
} from './gam';

const S: GamSettings = {
  gamPath: '/opt/gam7/gam',
  domains: { staff: 'example.org', students: 'students.example.org' },
  maxToTrashPerMailbox: 25,
  scanTimeoutSeconds: 1800,
  protectedSubjects: [...DEFAULT_PROTECTED_SUBJECTS],
  protectInternalSenders: true
};

describe('verifyQuery', () => {
  /**
   * The verify must measure the set the SWEEP touched. Without the protective suffix it
   * searches a wider set, so every responder copy the sweep deliberately spared returns
   * as a "survivor" and fires an alert email — every single time staff used the Phish
   * Alert Button. A verify that cries wolf by construction is one nobody reads.
   */
  it('applies the same protective exclusions the sweep used', () => {
    const q = verifyQuery(S, '"Download Transcript Record PDF"');
    expect(q).toContain('-from:example.org');
    for (const subj of DEFAULT_PROTECTED_SUBJECTS) {
      expect(q).toContain(`-subject:"${subj}"`);
    }
  });

  it('matches protectiveSuffix exactly, so the two cannot drift', () => {
    const q = verifyQuery(S, 'lure');
    expect(q).toContain(protectiveSuffix(S));
  });

  it('excludes Trash — anything returned survived the sweep', () => {
    expect(verifyQuery(S, 'lure')).toContain('-in:trash');
  });

  it('forces in:anywhere even when the operator query omitted it', () => {
    // The surviving copy in the founding incident was unlabelled and OUTSIDE the Inbox,
    // which a default-scope query cannot see. The verify inherits the operator's scope
    // query, so this cannot be left to chance.
    expect(verifyQuery(S, '"lure text"')).toContain('in:anywhere');
  });

  it('does not duplicate in:anywhere when it is already present', () => {
    const q = verifyQuery(S, '"lure" in:anywhere');
    expect(q.match(/in:anywhere/g)).toHaveLength(1);
  });

  it('honours protectInternalSenders being off', () => {
    const q = verifyQuery({ ...S, protectInternalSenders: false }, 'lure');
    expect(q).not.toContain('-from:example.org');
  });

  it('collapses whitespace rather than emitting double spaces', () => {
    const q = verifyQuery({ ...S, protectedSubjects: [], protectInternalSenders: false }, 'lure');
    expect(q).toBe('lure -in:trash in:anywhere');
  });
});

describe('flagsFromAccountCheck', () => {
  it('flags each persistence mechanism', () => {
    expect(flagsFromAccountCheck('Show 2 Filters')).toContain('HAS FILTERS');
    expect(flagsFromAccountCheck('Forward Enabled: True')).toContain('FORWARDING ON');
    expect(flagsFromAccountCheck('Show 1 Delegates')).toContain('DELEGATES');
    expect(flagsFromAccountCheck('Show 3 Application Specific Passwords')).toContain('APP PASSWORDS');
  });

  it('does not flag a zero count', () => {
    expect(flagsFromAccountCheck('Show 0 Filters')).toEqual([]);
  });

  /**
   * `show tokens` has been run since this check was written and its output was never
   * examined, while the Accounts page advertised "OAuth scopes" as covered.
   */
  it('flags an OAuth grant that can reach mail', () => {
    const blob = 'Client ID: 123\n  Scopes: https://www.googleapis.com/auth/gmail.settings.basic';
    expect(flagsFromAccountCheck(blob).join(' ')).toMatch(/OAUTH MAIL SCOPES/);
  });

  it('flags full mail.google.com access', () => {
    expect(flagsFromAccountCheck('Scopes: https://mail.google.com/').join(' ')).toMatch(
      /OAUTH MAIL SCOPES/
    );
  });

  it('does NOT flag routine ed-tech consent', () => {
    // "Allowing an app access to Google data" was 30 of 31 risky-action events in
    // September. A check that fires on every Chromebook app is a check that gets ignored.
    const routine =
      'Scopes: https://www.googleapis.com/auth/userinfo.email ' +
      'https://www.googleapis.com/auth/drive.file ' +
      'https://www.googleapis.com/auth/classroom.courses.readonly';
    expect(flagsFromAccountCheck(routine)).toEqual([]);
  });

  it('counts distinct scopes, not occurrences', () => {
    const blob =
      'Scopes: https://mail.google.com/\nScopes: https://mail.google.com/\n' +
      'Scopes: https://www.googleapis.com/auth/gmail.modify';
    expect(flagsFromAccountCheck(blob).join(' ')).toContain('2 distinct');
  });
});

describe('gamCompleted — exit 60 is not failure', () => {
  // Verbatim tail of a clean 1,364-mailbox scope on 2026-09-28 that exited 60.
  const clean = [
    'Getting all Messages that match query ((x)) for zoe.adams@example.org (1363/1364)',
    'Got 0 Messages that matched query ((x)) for zoe.adams@example.org...',
    'Getting all Messages that match query ((x)) for zara.young@example.org (1364/1364)',
    'Got 0 Messages that matched query ((x)) for zara.young@example.org...'
  ].join('\n');
  const died = 'Getting all Messages that match query ((x)) for m@example.org (300/1364)';

  it('accepts exit 0', () => expect(gamCompleted(0, false, '')).toBe(true));

  it('accepts exit 60 when GAM reached the last mailbox', () => {
    // Every domain-wide scope ends in 60, because most mailboxes match nothing. Rejecting
    // it kept the sweep gate permanently closed.
    expect(reachedEnd(clean)).toBe(true);
    expect(gamCompleted(60, false, clean)).toBe(true);
  });

  it('rejects exit 60 when the run stopped partway through', () => {
    expect(reachedEnd(died)).toBe(false);
    expect(gamCompleted(60, false, died)).toBe(false);
  });

  it('rejects exit 60 with no position lines at all', () => {
    expect(gamCompleted(60, false, 'Getting all Users...')).toBe(false);
  });

  it('never accepts a timeout, whatever the log says', () => {
    expect(gamCompleted(0, true, clean)).toBe(false);
    expect(gamCompleted(60, true, clean)).toBe(false);
  });

  it('rejects other non-zero exits even at N/N', () => {
    expect(gamCompleted(1, false, clean)).toBe(false);
  });
});

describe('assertSweepSafe — Message-ID', () => {
  it('accepts a single Message-ID — the narrowest query there is', () => {
    // Refused as "too broad" on 2026-09-29 while a BEC sat in one mailbox.
    expect(() => assertSweepSafe('rfc822msgid:eb44e982-586d-675a-bb99-1061f3ef1c15@gmail.com in:anywhere', S)).not.toThrow();
  });
  it('accepts a Message-ID alongside a sender', () => {
    expect(() => assertSweepSafe('from:x@gmail.com rfc822msgid:abc@gmail.com', S)).not.toThrow();
  });
  it('still refuses a bare sender', () => {
    expect(() => assertSweepSafe('from:x@gmail.com', S)).toThrow(/sender only/);
  });
  it('still refuses a genuinely broad query', () => {
    expect(() => assertSweepSafe('in:anywhere newer_than:7d', S)).toThrow(/too broad/);
  });
  it('still refuses targeting responder traffic, even by Message-ID', () => {
    expect(() => assertSweepSafe('rfc822msgid:abc@x subject:"[Phish Alert]"', S)).toThrow(/protected subject/);
  });
});

import { sweptMailboxes } from './gam';
describe('sweptMailboxes', () => {
  it('lists only mailboxes where the sweep actually acted', () => {
    const out = [
      'User: pat.morgan@example.org, Messages: 1, Trash 1 Messages',
      'User: zoe.adams@example.org, Messages: 0, Not Trashed: No Messages matched',
      'User: Nic.Fowler@example.org, Messages: 3, Trash 3 Messages'
    ].join('\n');
    expect(sweptMailboxes(out)).toEqual(['pat.morgan@example.org', 'nic.fowler@example.org']);
  });
  it('returns nothing for a sweep that matched nothing', () => {
    expect(sweptMailboxes('User: a@b.org, Messages: 0, No Messages matched')).toEqual([]);
  });
});

describe('trashIdsArgs / labelIdsArgs (hand-picked containment)', () => {
  it('builds a trash-by-ids command for a valid mailbox and ids', () => {
    expect(trashIdsArgs('alex@example.org', ['18ab', '19cd'])).toEqual([
      'user', 'alex@example.org', 'trash', 'messages', 'ids', '18ab,19cd', 'doit'
    ]);
  });

  it('lower-cases the mailbox and drops ids with illegal characters', () => {
    expect(trashIdsArgs('Alex@Example.ORG', ['ok_1', 'bad id', 'a,b', 'fine-2'])).toEqual([
      'user', 'alex@example.org', 'trash', 'messages', 'ids', 'ok_1,fine-2', 'doit'
    ]);
  });

  it('returns null for a bad mailbox or when no id survives validation', () => {
    expect(trashIdsArgs('not-an-email', ['18ab'])).toBeNull();
    expect(trashIdsArgs('alex@example.org', [])).toBeNull();
    expect(trashIdsArgs('alex@example.org', ['', ' ', 'a b'])).toBeNull();
  });

  it('builds a label-by-ids command and requires a non-empty label', () => {
    expect(labelIdsArgs('alex@example.org', ['18ab'], '⚠ PHISHING')).toEqual([
      'user', 'alex@example.org', 'modify', 'messages', 'ids', '18ab', 'addlabel', '⚠ PHISHING', 'doit'
    ]);
    expect(labelIdsArgs('alex@example.org', ['18ab'], '   ')).toBeNull();
  });
});

describe('gamPathReason (GAM binary path guard)', () => {
  it('accepts a normal absolute install path', () => {
    expect(gamPathReason('/opt/gam7/gam')).toBeNull();
    expect(gamPathReason('/usr/local/bin/gam')).toBeNull();
  });

  it('rejects relative paths, whitespace, and temp/user-writable locations', () => {
    expect(gamPathReason('gam')).toMatch(/absolute/);
    expect(gamPathReason('relative/gam')).toMatch(/absolute/);
    expect(gamPathReason('/tmp/evil')).toMatch(/temporary or user-writable/);
    expect(gamPathReason('/var/tmp/x')).toMatch(/temporary or user-writable/);
    expect(gamPathReason('/var/lib/warden/.gam/evil')).toMatch(/temporary or user-writable/);
    expect(gamPathReason('/home/admin/gam')).toMatch(/temporary or user-writable/);
    expect(gamPathReason('/opt/gam7/gam x')).toMatch(/whitespace/);
    expect(gamPathReason('')).toMatch(/not set/);
  });
});

describe('parseRemovableItems (kill persistence)', () => {
  const blob = [
    '===== printfilters (exit 0) =====',
    'User,id,from,subject,query,hasAttachment,forward,archive,important,label,markread,star,neverspam,trash',
    'victim@example.org,ANe1BmgEVIL123,,,query from:attacker@evil.test,,,,,,,,,trash',
    'victim@example.org,ANe1BmgGOOD456,from newsletter@example.org,,,,,archive,,label News,,,,',
    '===== printforwardingaddresses (exit 0) =====',
    'User,forwardingEmail,verificationStatus',
    'victim@example.org,attacker@evil.test,accepted',
    '===== printdelegates (exit 0) =====',
    'User,delegateAddress,delegationStatus',
    'victim@example.org,spy@evil.test,ACCEPTED',
    '===== forward (exit 0) =====',
    'User: victim@example.org, Forward Enabled: True, Forwarding Address: attacker@evil.test, Action: KEEP'
  ].join('\n');

  it('extracts each removable item with the id/address a remove needs', () => {
    const items = parseRemovableItems(blob);
    const filters = items.filter((i) => i.kind === 'filter').map((i) => i.target);
    expect(filters).toEqual(['ANe1BmgEVIL123', 'ANe1BmgGOOD456']);
    expect(items.find((i) => i.kind === 'forwardingaddress')?.target).toBe('attacker@evil.test');
    expect(items.find((i) => i.kind === 'delegate')?.target).toBe('spy@evil.test');
    expect(items.some((i) => i.kind === 'forward_off')).toBe(true);
    // the evil filter's label carries its criteria/action so an operator can tell them apart
    expect(items.find((i) => i.target === 'ANe1BmgEVIL123')?.label).toMatch(/attacker@evil\.test/);
  });

  it('returns nothing when forwarding is off and there are no filters/delegates', () => {
    const clean = [
      '===== printfilters (exit 0) =====', 'User,id,from,subject,query',
      '===== printforwardingaddresses (exit 0) =====', 'User,forwardingEmail,verificationStatus',
      '===== printdelegates (exit 0) =====', 'User,delegateAddress,delegationStatus',
      '===== forward (exit 0) =====', 'User: victim@example.org, Forward Enabled: False'
    ].join('\n');
    expect(parseRemovableItems(clean)).toEqual([]);
  });
});
