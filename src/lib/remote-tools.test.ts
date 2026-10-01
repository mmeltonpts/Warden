import { describe, it, expect } from 'vitest';
import { classify, matchTool, isServiceUser, splitList, type ToolRow } from './remote-tools';

const row = (p: Partial<ToolRow>): ToolRow => ({
  tool: 'x', appName: 'PuTTY suite', version: null, hostname: 'IT-PC-01',
  lastUser: 'jane.tech', lastUsedAt: null, fileName: null, ...p
});

describe('classify', () => {
  const banned = ['ScreenConnect', 'ConnectWise'];

  it('bans ScreenConnect whatever the approved list says', () => {
    // Approval must never be able to override a ban.
    expect(classify(row({ appName: 'ScreenConnect Client (0123456789abcdef)' }), banned, ['ScreenConnect'])).toBe('banned');
  });

  it('approves a tool for a named person only', () => {
    expect(classify(row({}), banned, ['PuTTY@jane.tech'])).toBe('approved');
    expect(classify(row({ lastUser: 'stu.dent1', hostname: 'DESKTOP-ABC1234' }), banned, ['PuTTY@jane.tech'])).toBe('unapproved');
  });

  it('approves a tool on a named PC', () => {
    expect(classify(row({ appName: 'Parsec', hostname: 'LAB-PC-01', lastUser: 'S-1-5-18' }), banned, ['Parsec@LAB-PC-01'])).toBe('approved');
  });

  it('matches a person whether Falcon reports DOMAIN\\user or user@domain', () => {
    expect(classify(row({ lastUser: String.raw`DISTRICT\jane.tech@example.org` }), banned, ['PuTTY@jane.tech'])).toBe('approved');
  });

  it('approves everywhere with no scope', () => {
    expect(classify(row({ appName: 'Splashtop Wired XDisplay' }), banned, ['Splashtop'])).toBe('approved');
  });

  it('flags anything not listed', () => {
    expect(classify(row({ appName: 'AnyDesk' }), banned, [])).toBe('unapproved');
  });
});

describe('helpers', () => {
  it('matchTool is case-insensitive and returns the watch entry', () => {
    expect(matchTool('Royal TS V7', ['PuTTY', 'Royal TS'])).toBe('Royal TS');
    expect(matchTool('Notepad', ['PuTTY'])).toBeNull();
  });
  it('isServiceUser spots SYSTEM and machine accounts', () => {
    expect(isServiceUser('S-1-5-18')).toBe(true);
    expect(isServiceUser('DESKTOP-ABC1234$')).toBe(true);
    expect(isServiceUser('jane.tech')).toBe(false);
  });
  it('splitList accepts commas and newlines', () => {
    expect(splitList('a, b\nc,,')).toEqual(['a', 'b', 'c']);
  });
});
