import { describe, it, expect } from 'vitest';
import { collapseByNetwork, nearestGrant, type ScoredFlag } from './loginscan';
import { MAIL_SCOPE } from './gam';

const f = (p: Partial<ScoredFlag>): ScoredFlag => ({
  ts: new Date('2026-10-05T00:19:00Z'), score: 50, reasons: ['New network for this user'],
  ip: '198.51.100.140', asn: 'AS36180', geo: 'US-TX', challenge: null, suspicious: false, ...p
});

describe('collapseByNetwork', () => {
  it('collapses repeated sign-ins from the same network into one flag', () => {
    // A staff phone: four sign-ins, same /24, same minute, identical risk signature.
    const out = collapseByNetwork([
      f({ ts: new Date('2026-10-05T00:18:30Z') }),
      f({ ts: new Date('2026-10-05T00:19:01Z') }),
      f({ ts: new Date('2026-10-05T00:19:20Z') }),
      f({ ts: new Date('2026-10-05T00:19:40Z') })
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].reasons.join(' ')).toMatch(/4 sign-ins from this network/);
  });

  it('keeps the worst-scoring event in a collapsed group', () => {
    const out = collapseByNetwork([
      f({ score: 50, reasons: ['New network for this user'] }),
      f({ score: 85, suspicious: true, reasons: ['Google flagged this sign-in as suspicious', 'New network for this user'] })
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].score).toBe(85);
    expect(out[0].suspicious).toBe(true);
    expect(out[0].reasons.join(' ')).toMatch(/suspicious/);
  });

  it('never merges different networks', () => {
    const out = collapseByNetwork([
      f({ ip: '198.51.100.140', geo: 'US-TX' }),
      f({ ip: '203.0.113.9', geo: 'US-CA', score: 60 })
    ]);
    expect(out).toHaveLength(2);
    expect(out[0].score).toBe(60); // sorted worst-first
  });

  it('collapses an IPv6 burst on the /48', () => {
    const out = collapseByNetwork([
      f({ ip: '2001:db8:abcd:1:2:3:4:5' }),
      f({ ip: '2001:db8:abcd:9:8:7:6:5' })
    ]);
    expect(out).toHaveLength(1);
  });

  it('passes a single flag through unchanged', () => {
    const out = collapseByNetwork([f({})]);
    expect(out).toHaveLength(1);
    expect(out[0].reasons).toEqual(['New network for this user']);
  });
});

/**
 * nearestGrant resolves the app behind a sign-in's "app access" sensitive action from the
 * token log. Columns found by NAME; empty/failed CSV returns null (never a benign answer).
 * Invented data only — example.edu and made-up apps, never district accounts.
 */
describe('nearestGrant', () => {
  const HEADER =
    'name,actor.email,actor.profileId,app_name,client_id,client_type,id.applicationName,' +
    'id.customerId,id.time,id.uniqueQualifier,ipAddress,isAgenticAction,networkInfo.ipAsn,' +
    'networkInfo.ipAsn.0,networkInfo.regionCode,networkInfo.subdivisionCode,product_bucket,scope,type';
  const IDENTITY =
    'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid';
  const MAIL = 'https://mail.google.com/ https://www.googleapis.com/auth/gmail.modify';
  const row = (app: string, time: string, scope: string) =>
    `authorize,alex@example.edu,111,${app},cid,WEB,token,C1,${time},uq,203.0.113.5,False,1,174,US,US-IN,GMAIL,${scope},auth`;
  const csv = [
    HEADER,
    row('Reader App', '2026-10-05T16:26:31Z', IDENTITY),
    row('Service Mailer', '2026-10-05T16:19:12Z', MAIL)
  ].join('\n');

  it('picks the authorize nearest the sign-in, and reads an identity-only grant as no-mail', () => {
    const g = nearestGrant(csv, new Date('2026-10-05T16:26:22Z'), MAIL_SCOPE);
    expect(g).toEqual({ name: 'Reader App', mailAccess: false });
  });

  it('flags a mail-capable grant when it is the one nearest the event', () => {
    const g = nearestGrant(csv, new Date('2026-10-05T16:19:15Z'), MAIL_SCOPE);
    expect(g).toEqual({ name: 'Service Mailer', mailAccess: true });
  });

  it('returns null for an empty or header-only CSV — a failed lookup is not a clean answer', () => {
    expect(nearestGrant('', new Date(), MAIL_SCOPE)).toBeNull();
    expect(nearestGrant(HEADER, new Date(), MAIL_SCOPE)).toBeNull();
  });

  it('returns null when the scope column is absent rather than guessing', () => {
    const noScope = ['name,app_name,id.time', 'authorize,X,2026-10-05T16:26:31Z'].join('\n');
    expect(nearestGrant(noScope, new Date('2026-10-05T16:26:22Z'), MAIL_SCOPE)).toBeNull();
  });
});
