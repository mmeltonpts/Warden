import { describe, it, expect } from 'vitest';
import {
  parseGrantEvents,
  isAllowed,
  mailScopesOf,
  selectGrantFlags,
  type GrantEvent,
  type GrantAllow
} from './oauth-grants';

const HEADER =
  'name,actor.email,actor.profileId,app_name,client_id,client_type,id.applicationName,' +
  'id.customerId,id.time,id.uniqueQualifier,ipAddress,isAgenticAction,networkInfo.ipAsn,' +
  'networkInfo.ipAsn.0,networkInfo.regionCode,networkInfo.subdivisionCode,product_bucket,scope,type';
const MAIL = 'https://mail.google.com/ https://www.googleapis.com/auth/gmail.modify';
const IDENTITY = 'https://www.googleapis.com/auth/userinfo.email openid';

const row = (o: {
  name?: string; email: string; app: string; client: string; time: string; ip?: string; scope: string;
}) =>
  `${o.name ?? 'authorize'},${o.email},111,${o.app},${o.client},WEB,token,C1,${o.time},uq,` +
  `${o.ip ?? '203.0.113.5'},False,1,174,US,US-IN,GMAIL,${o.scope},auth`;

const allow = (over: Partial<GrantAllow> = {}): GrantAllow => ({
  clientIds: new Set<string>(),
  namePatterns: [],
  ...over
});

describe('parseGrantEvents', () => {
  it('parses authorize rows for the configured domains, columns by name', () => {
    const csv = [
      HEADER,
      row({ email: 'alex@example.edu', app: 'Some Mailer', client: 'c1', time: '2026-10-05T16:26:31Z', scope: MAIL }),
      row({ email: 'kid@student.example.edu', app: 'Reader', client: 'c2', time: '2026-10-05T16:20:00Z', scope: IDENTITY })
    ].join('\n');
    const out = parseGrantEvents(csv, ['example.edu']);
    expect(out).toHaveLength(1); // the student domain is not in the list
    expect(out[0]).toMatchObject({ mailbox: 'alex@example.edu', appName: 'Some Mailer', clientId: 'c1' });
    expect(out[0].scopes).toContain('https://mail.google.com/');
  });

  it('skips non-authorize events (a revoke is not a grant)', () => {
    const csv = [
      HEADER,
      row({ name: 'revoke', email: 'alex@example.edu', app: 'X', client: 'c1', time: '2026-10-05T16:26:31Z', scope: MAIL })
    ].join('\n');
    expect(parseGrantEvents(csv, ['example.edu'])).toHaveLength(0);
  });

  it('returns [] for an empty or header-only CSV — saw nothing, not a benign answer', () => {
    expect(parseGrantEvents('', ['example.edu'])).toEqual([]);
    expect(parseGrantEvents(HEADER, ['example.edu'])).toEqual([]);
  });
});

describe('mailScopesOf / isAllowed', () => {
  const ev = (o: Partial<GrantEvent>): GrantEvent => ({
    mailbox: 'alex@example.edu', ts: new Date('2026-10-05T16:26:31Z'), appName: 'App',
    clientId: 'c1', clientType: 'WEB', scopes: MAIL.split(' '), ip: null, ...o
  });

  it('extracts only the mail-capable scopes', () => {
    expect(mailScopesOf([...MAIL.split(' '), 'openid'])).toEqual([
      'https://mail.google.com/',
      'https://www.googleapis.com/auth/gmail.modify'
    ]);
  });

  it('allow-lists by exact client id (the trustworthy control)', () => {
    expect(isAllowed(ev({ clientId: 'c1' }), allow({ clientIds: new Set(['c1']) }))).toBe(true);
    expect(isAllowed(ev({ clientId: 'c2' }), allow({ clientIds: new Set(['c1']) }))).toBe(false);
  });

  it('allow-lists by name substring, case-insensitively (a convenience)', () => {
    expect(isAllowed(ev({ appName: 'Microsoft Outlook' }), allow({ namePatterns: ['outlook'] }))).toBe(true);
    expect(isAllowed(ev({ appName: 'Evil App' }), allow({ namePatterns: ['outlook'] }))).toBe(false);
  });
});

describe('selectGrantFlags', () => {
  const E = (o: Partial<GrantEvent>): GrantEvent => ({
    mailbox: 'alex@example.edu', ts: new Date('2026-10-05T16:26:31Z'), appName: 'Suspicious Mailer',
    clientId: 'evil', clientType: 'WEB', scopes: MAIL.split(' '), ip: '198.51.100.9', ...o
  });

  it('flags a single-mailbox mail-capable grant to an unknown app', () => {
    const flags = selectGrantFlags([E({})], allow());
    expect(flags).toHaveLength(1);
    expect(flags[0].fanOut).toBe(1);
    expect(flags[0].reasons.join(' ')).toMatch(/targeted token takeover/);
  });

  it('does not flag an identity-only grant', () => {
    const flags = selectGrantFlags([E({ scopes: IDENTITY.split(' ') })], allow());
    expect(flags).toHaveLength(0);
  });

  it('does not flag an allow-listed app', () => {
    const flags = selectGrantFlags([E({ clientId: 'known' })], allow({ clientIds: new Set(['known']) }));
    expect(flags).toHaveLength(0);
  });

  it('dedups to one flag per (mailbox, client), keeping the latest timestamp', () => {
    const flags = selectGrantFlags(
      [
        E({ ts: new Date('2026-10-05T16:00:00Z') }),
        E({ ts: new Date('2026-10-05T16:30:00Z') }),
        E({ ts: new Date('2026-10-05T16:15:00Z') })
      ],
      allow()
    );
    expect(flags).toHaveLength(1);
    expect(flags[0].ts.toISOString()).toBe('2026-10-05T16:30:00.000Z');
  });

  it('computes fan-out and sorts single-mailbox grants ahead of enterprise rollouts', () => {
    const flags = selectGrantFlags(
      [
        // Enterprise rollout: one app on three mailboxes
        E({ mailbox: 'a@example.edu', clientId: 'rollout', appName: 'Big Suite' }),
        E({ mailbox: 'b@example.edu', clientId: 'rollout', appName: 'Big Suite' }),
        E({ mailbox: 'c@example.edu', clientId: 'rollout', appName: 'Big Suite' }),
        // Targeted: one app on one mailbox
        E({ mailbox: 'victim@example.edu', clientId: 'evil', appName: 'Suspicious Mailer' })
      ],
      allow()
    );
    // 3 rollout flags (dedup per mailbox) + 1 targeted = 4
    expect(flags).toHaveLength(4);
    // The targeted single-mailbox grant sorts first
    expect(flags[0].clientId).toBe('evil');
    expect(flags[0].fanOut).toBe(1);
    expect(flags.find((f) => f.clientId === 'rollout')!.fanOut).toBe(3);
    expect(flags.find((f) => f.clientId === 'rollout')!.reasons.join(' ')).toMatch(/enterprise or ed-tech rollout/);
  });
});
