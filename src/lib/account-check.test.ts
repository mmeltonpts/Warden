import { describe, it, expect } from 'vitest';
import { parseAccountCheck, parseOAuthApps } from './gam';

// A real clean account: an iPhone (native Mail has the mail scope) and some ed-tech apps.
const CLEAN = `===== filters (exit 0) =====
User: a@example.org, Show 0 Filters

===== forward (exit 0) =====
User: a@example.org, Forward Enabled: False

===== forwardingaddresses (exit 0) =====
User: a@example.org, Show 0 Forwarding Addresses

===== delegates (exit 0) =====
User: a@example.org, Show 0 Delegates

===== asps (exit 60) =====
User: a@example.org, Show 0 Application Specific Password IDs

===== tokens (exit 0) =====
User: a@example.org, Show 2 Access Tokens
  Client ID: 450232826690-x.apps.googleusercontent.com (1/2)
    displayText: iOS
    scopes:
      https://mail.google.com/
      https://www.googleapis.com/auth/calendar
  Client ID: 61422126263-y.apps.googleusercontent.com (2/2)
    displayText: eFinance25
    scopes:
      https://www.googleapis.com/auth/userinfo.email
      openid
`;

describe('parseAccountCheck', () => {
  it('reports clean mechanisms by name, not silence', () => {
    const r = parseAccountCheck(CLEAN);
    const byName = Object.fromEntries(r.mechanisms.map((m) => [m.name, m]));
    expect(byName['Filters'].status).toBe('clean');
    expect(byName['Filters'].summary).toBe('none');
    expect(byName['Forwarding'].summary).toBe('off');
    expect(byName['Delegates'].summary).toBe('none');
    expect(byName['App passwords'].summary).toBe('none');
  });

  it('names the app that holds a mail scope, and the overall verdict is review', () => {
    const r = parseAccountCheck(CLEAN);
    const apps = r.mechanisms.find((m) => m.name.startsWith('Connected apps'))!;
    expect(apps.status).toBe('review');
    expect(apps.detail.join(' ')).toContain('iOS');
    expect(r.verdict).toBe('review'); // a mail-capable app is worth a human glance, not alarm
    expect(r.apps.filter((a) => a.mailAccess).map((a) => a.name)).toEqual(['iOS']);
  });

  it('flags filters, forwarding and delegates as review', () => {
    const blob = `===== filters (exit 0) =====
User: b@example.org, Show 1 Filters
  Filter: abc criteria: from attacker@evil.example action: trash
===== forward (exit 0) =====
User: b@example.org, Forward Enabled: True Forwarding Address: exfil@evil.example Action: archive
===== forwardingaddresses (exit 0) =====
User: b@example.org, Show 0 Forwarding Addresses
===== delegates (exit 0) =====
User: b@example.org, Show 1 Delegates
  Delegate: attacker@evil.example
===== asps (exit 0) =====
User: b@example.org, Show 0 Application Specific Password IDs
===== tokens (exit 0) =====
User: b@example.org, Show 0 Access Tokens
`;
    const r = parseAccountCheck(blob);
    const m = Object.fromEntries(r.mechanisms.map((x) => [x.name, x]));
    expect(m['Filters'].status).toBe('review');
    expect(m['Filters'].detail.join(' ')).toContain('attacker@evil.example');
    expect(m['Forwarding'].summary).toContain('exfil@evil.example');
    expect(m['Delegates'].status).toBe('review');
    expect(r.verdict).toBe('review');
  });

  it('a check that did not complete makes the whole result inconclusive', () => {
    const blob = `===== filters (exit 1) =====
User: c@example.org, error
===== forward (exit 0) =====
User: c@example.org, Forward Enabled: False
===== forwardingaddresses (exit 0) =====
User: c@example.org, Show 0 Forwarding Addresses
===== delegates (exit 0) =====
User: c@example.org, Show 0 Delegates
===== asps (exit 0) =====
User: c@example.org, Show 0 Application Specific Password IDs
===== tokens (exit 0) =====
User: c@example.org, Show 0 Access Tokens
`;
    const r = parseAccountCheck(blob);
    expect(r.verdict).toBe('inconclusive');
    expect(r.mechanisms.find((m) => m.name === 'Filters')!.status).toBe('failed');
  });
});

describe('parseOAuthApps', () => {
  it('splits apps and detects mail access', () => {
    const apps = parseOAuthApps(`  Client ID: aaa (1/2)
    displayText: Thunderbird
    scopes:
      https://mail.google.com/
  Client ID: bbb (2/2)
    displayText: Zoom
    scopes:
      https://www.googleapis.com/auth/calendar
`);
    expect(apps).toHaveLength(2);
    expect(apps[0]).toMatchObject({ name: 'Thunderbird', mailAccess: true });
    expect(apps[1]).toMatchObject({ name: 'Zoom', mailAccess: false });
  });
});
