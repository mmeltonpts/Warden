import { describe, it, expect } from 'vitest';
import {
  isExternal,
  parseForwardingAddresses,
  parseDelegates,
  parseActiveForward,
  itemReasons
} from './forwarding-watch';

const DOMAINS = ['example.edu', 'student.example.edu'];

describe('isExternal', () => {
  it('treats the district domain and its subdomains as internal', () => {
    expect(isExternal('a@example.edu', DOMAINS)).toBe(false);
    expect(isExternal('b@student.example.edu', DOMAINS)).toBe(false);
    expect(isExternal('c@mail.example.edu', DOMAINS)).toBe(false); // subdomain of example.edu
  });
  it('treats any other domain as external', () => {
    expect(isExternal('x@gmail.com', DOMAINS)).toBe(true);
    expect(isExternal('y@notexample.edu', DOMAINS)).toBe(true); // look-alike is not the district
  });
  it('does not manufacture an alarm from a malformed address', () => {
    expect(isExternal('not-an-address', DOMAINS)).toBe(false);
    expect(isExternal('', DOMAINS)).toBe(false);
  });
});

describe('parseForwardingAddresses', () => {
  const csv = [
    'User,forwardingEmail,verificationStatus',
    'alice@example.edu,backup@example.edu,accepted',
    'bob@example.edu,attacker@evil.test,accepted',
    'carol@example.edu,,' // no address — skipped
  ].join('\n');

  it('extracts registered forwarding addresses and flags the external one', () => {
    const items = parseForwardingAddresses(csv, DOMAINS);
    expect(items).toHaveLength(2);
    const bob = items.find((i) => i.mailbox === 'bob@example.edu')!;
    expect(bob).toMatchObject({ kind: 'forwardingaddress', target: 'attacker@evil.test', external: true });
    expect(items.find((i) => i.mailbox === 'alice@example.edu')!.external).toBe(false);
  });

  it('returns [] for empty or header-only input', () => {
    expect(parseForwardingAddresses('', DOMAINS)).toEqual([]);
    expect(parseForwardingAddresses('User,forwardingEmail,verificationStatus', DOMAINS)).toEqual([]);
  });
});

describe('parseDelegates', () => {
  it('flags an external delegate, records an internal one', () => {
    const csv = [
      'User,delegateAddress,delegationStatus',
      'principal@example.edu,assistant@example.edu,accepted',
      'cfo@example.edu,thief@evil.test,accepted'
    ].join('\n');
    const items = parseDelegates(csv, DOMAINS);
    expect(items).toHaveLength(2);
    expect(items.find((i) => i.target === 'thief@evil.test')!.external).toBe(true);
    expect(items.find((i) => i.target === 'assistant@example.edu')!.external).toBe(false);
    expect(items[0].kind).toBe('delegate');
  });
});

describe('parseActiveForward', () => {
  it('only yields ENABLED forwards, with external classification', () => {
    const text = [
      'User: a@example.edu, Forward Enabled: True, Forwarding Address: out@evil.test, Action: leaveInInbox',
      'User: b@example.edu, Forward Enabled: False',
      'User: c@example.edu, Forward Enabled: True, Forwarding Address: team@example.edu, Action: KEEP'
    ].join('\n');
    const items = parseActiveForward(text, DOMAINS);
    expect(items).toHaveLength(2);
    expect(items.find((i) => i.mailbox === 'a@example.edu')).toMatchObject({
      kind: 'forward',
      target: 'out@evil.test',
      external: true,
      detail: 'leaveInInbox'
    });
    expect(items.find((i) => i.mailbox === 'b@example.edu')).toBeUndefined(); // disabled
    expect(items.find((i) => i.mailbox === 'c@example.edu')!.external).toBe(false);
  });
});

describe('itemReasons', () => {
  it('leads with exfil wording for an external target', () => {
    const r = itemReasons({ mailbox: 'x@example.edu', kind: 'forward', target: 'o@evil.test', external: true });
    expect(r.join(' ')).toMatch(/OUTSIDE the district/);
  });
  it('notes an internal target as ordinary', () => {
    const r = itemReasons({ mailbox: 'x@example.edu', kind: 'delegate', target: 'a@example.edu', external: false });
    expect(r.join(' ')).toMatch(/ordinary for a shared role/);
  });
});
