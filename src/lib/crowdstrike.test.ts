import { describe, it, expect } from 'vitest';
import { falconBase, falconConsole, falconHostLink } from './crowdstrike';

describe('falconConsole — console host derives from the API host', () => {
  it('maps commercial clouds', () => {
    expect(falconConsole('us-1')).toBe('https://falcon.crowdstrike.com');
    expect(falconConsole('us-2')).toBe('https://falcon.us-2.crowdstrike.com');
    expect(falconConsole('eu-1')).toBe('https://falcon.eu-1.crowdstrike.com');
  });
  it('maps GovCloud', () => {
    expect(falconConsole('us-gov-1')).toBe('https://falcon.laggar.gcw.crowdstrike.com');
    expect(falconConsole('us-gov-2')).toBe('https://falcon.us-gov-2.crowdstrike.mil');
  });
  it('accepts the API base URL form the operator pastes', () => {
    expect(falconConsole('https://api.laggar.gcw.crowdstrike.com')).toBe('https://falcon.laggar.gcw.crowdstrike.com');
    expect(falconBase('us-gov-1')).toBe('https://api.laggar.gcw.crowdstrike.com');
  });
  it('returns null for an unknown cloud, so a link is only built to a real host', () => {
    expect(falconConsole('evil.example')).toBeNull();
    expect(falconConsole('')).toBeNull();
  });
});

describe('falconHostLink — read-only deep-link to the host', () => {
  it('links to the host detail page by device id', () => {
    expect(falconHostLink('us-1', 'aid-123')).toBe('https://falcon.crowdstrike.com/host-management/hosts/aid-123');
  });
  it('falls back to the inventory when no device id is known', () => {
    expect(falconHostLink('us-1', null)).toBe('https://falcon.crowdstrike.com/host-management/hosts-inventory');
  });
  it('is null for an unknown cloud', () => {
    expect(falconHostLink('evil.example', 'aid-123')).toBeNull();
  });
});
