/**
 * Regression tests for the risk engine, built from the real September 2026 incidents.
 *
 * Every case below is a sign-in that actually happened. Two were genuine account
 * takeovers; the rest are the noise that a naive rule flagged instead. If a change to
 * the scoring stops separating these, it is wrong regardless of how reasonable it looks.
 */
import { describe, it, expect } from 'vitest';
import { buildBaseline, assessRisk, ipPrefix, FLAG_THRESHOLD, type RawLoginEvent } from './baseline';

const at = (iso: string) => new Date(iso);

/** A mailbox that normally signs in from the district and one home ISP. */
function normalHistory(mailbox: string): RawLoginEvent[] {
  const out: RawLoginEvent[] = [];
  for (let d = 1; d <= 12; d++) {
    const day = String(d).padStart(2, '0');
    out.push({
      mailbox, ts: at(`2026-09-${day}T13:00:00Z`), eventName: 'login_success',
      ip: '203.0.113.25', asn: '13428', geo: 'US-IN', challenge: 'none', suspicious: false
    });
    out.push({
      mailbox, ts: at(`2026-09-${day}T23:30:00Z`), eventName: 'login_success',
      ip: '50.102.9.94', asn: '5650', geo: 'US-IN', challenge: 'password', suspicious: false
    });
  }
  return out;
}

describe('ipPrefix', () => {
  it('learns v4 on the /24, not the address', () => {
    expect(ipPrefix('203.0.113.25')).toBe('203.0.113.0/24');
    expect(ipPrefix('203.0.113.99')).toBe('203.0.113.0/24');
  });

  it('learns v6 on the /48 — consumer IPv6 rotates low bits every reconnect', () => {
    expect(ipPrefix('2600:387:15:2c17:0:0:0:1')).toBe('2600:387:15::/48');
    expect(ipPrefix('2600:387:15:2c17:abcd:ef01:2345:6789')).toBe('2600:387:15::/48');
  });

  it('tolerates junk', () => {
    expect(ipPrefix(null)).toBeNull();
    expect(ipPrefix('not-an-ip')).toBeNull();
  });
});

describe('buildBaseline', () => {
  it('requires two sightings before a network counts as normal', () => {
    const mailbox = 'x@example.edu';
    const events: RawLoginEvent[] = [
      ...normalHistory(mailbox),
      // a single visit to a new network — exactly what a first intrusion looks like
      { mailbox, ts: at('2026-09-20T02:00:00Z'), eventName: 'login_success',
        ip: '198.51.100.7', asn: '64500', geo: 'US-TX', challenge: 'password', suspicious: false }
    ];
    const b = buildBaseline(mailbox, events);
    // The established network, seen many times, is normal.
    expect(b.knownPrefixes).toContain('203.0.113.0/24');
    // The one-off is NOT. Seen once is what a first intrusion looks like.
    expect(b.knownPrefixes).not.toContain('198.51.100.0/24');
  });

  it('marks a thin history immature', () => {
    const b = buildBaseline('new@example.edu', [
      { mailbox: 'new@example.edu', ts: at('2026-09-20T12:00:00Z'),
        eventName: 'login_success', ip: '203.0.113.2', asn: '13428', geo: 'US-IN' }
    ]);
    expect(b.mature).toBe(false);
  });
});

describe('real incidents — must flag', () => {
  it('compromised.one 2026-09-13: Cogent AS174, suspicious, phone challenge passed', () => {
    const mailbox = 'compromised.one@example.edu';
    const baseline = buildBaseline(mailbox, normalHistory(mailbox));
    const r = assessRisk(
      { mailbox, ts: at('2026-09-13T19:18:46Z'), eventName: 'login_success',
        ip: '192.0.2.68', asn: '174', geo: 'US-NY',
        challenge: 'password idv_preregistered_phone', suspicious: true },
      baseline
    );
    expect(r.flag).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(90);
  });

  it('compromised.one: filter creation scores highest of all', () => {
    const mailbox = 'compromised.one@example.edu';
    const baseline = buildBaseline(mailbox, normalHistory(mailbox));
    const r = assessRisk(
      { mailbox, ts: at('2026-09-13T19:21:46Z'), eventName: 'login_success',
        ip: '192.0.2.68', asn: '174', geo: 'US-NY', challenge: 'reauth', suspicious: true,
        sensitive: 'Access sensitive Gmail action (e.g. filters without forwarding)' },
      baseline
    );
    expect(r.flag).toBe(true);
    expect(r.reasons.some((x) => /Sensitive Gmail action/.test(x))).toBe(true);
  });

  it('compromised.two 2026-09-22: AS40317 Texas, suspicious, phone challenge passed', () => {
    const mailbox = 'compromised.two@example.edu';
    const baseline = buildBaseline(mailbox, normalHistory(mailbox));
    const r = assessRisk(
      { mailbox, ts: at('2026-09-22T18:48:46Z'), eventName: 'login_success',
        ip: '167.89.225.47', asn: '40317', geo: 'US-TX',
        challenge: 'password idv_preregistered_phone', suspicious: true },
      baseline
    );
    expect(r.flag).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(90);
  });
});

describe('real noise — must NOT flag', () => {
  it('passkey users flagged by Google are safe: the challenge cannot be relayed', () => {
    // passkey.user / passkey.user2, both is_suspicious=true in the same week.
    const mailbox = 'passkey.user@example.edu';
    const baseline = buildBaseline(mailbox, normalHistory(mailbox));
    const r = assessRisk(
      { mailbox, ts: at('2026-09-15T03:05:29Z'), eventName: 'login_success',
        ip: '2600:1015:b20b:ba78::1', asn: '6167', geo: 'US-IN',
        challenge: 'password passkey', suspicious: true },
      baseline
    );
    expect(r.flag).toBe(false);
    expect(r.reasons.some((x) => /passkey/i.test(x))).toBe(true);
  });

  it('a known home network with a routine push prompt is not a finding', () => {
    const mailbox = 'routine.user@example.edu';
    const history = normalHistory(mailbox);
    // home ISP seen repeatedly => part of normal
    for (let d = 1; d <= 6; d++) {
      history.push({
        mailbox, ts: at(`2026-09-0${d}T02:00:00Z`), eventName: 'login_success',
        ip: '50.102.12.114', asn: '13428', geo: 'US-IN',
        challenge: 'password device_prompt', suspicious: false
      });
    }
    const baseline = buildBaseline(mailbox, history);
    const r = assessRisk(
      { mailbox, ts: at('2026-09-18T02:19:14Z'), eventName: 'login_success',
        ip: '50.102.12.114', asn: '13428', geo: 'US-IN',
        challenge: 'password device_prompt', suspicious: false },
      baseline
    );
    expect(r.flag).toBe(false);
  });

  it('"Allowing an app access to Google data" is ed-tech OAuth consent, not compromise', () => {
    // 30 of 31 risky-action events in September were this. Only filter creation mattered.
    const mailbox = 'consent.user@example.edu';
    const baseline = buildBaseline(mailbox, normalHistory(mailbox));
    const r = assessRisk(
      { mailbox, ts: at('2026-09-22T22:01:19Z'), eventName: 'login_success',
        ip: '50.102.9.94', asn: '5650', geo: 'US-IN', challenge: 'none', suspicious: false,
        sensitive: 'Allowing an app access to Google data' },
      baseline
    );
    expect(r.flag).toBe(false);
  });

  it('non-success events are ignored — a failed challenge is not a takeover', () => {
    const mailbox = 'x@example.edu';
    const r = assessRisk(
      { mailbox, ts: at('2026-09-22T10:00:00Z'), eventName: 'login_challenge',
        ip: '203.0.113.9', asn: '174', geo: 'US-NY',
        challenge: 'idv_preregistered_phone', suspicious: true },
      buildBaseline(mailbox, normalHistory(mailbox))
    );
    expect(r.score).toBe(0);
  });
});

describe('ambiguous cases keep the human in the loop', () => {
  it('carrier.user: AT&T IPv6 geolocating to Texas is surfaced, not auto-condemned', () => {
    // District login at 19:19, "Texas" at 19:21. Physically impossible, but AS7018 is
    // AT&T Mobility and its IPv6 geolocates to Texas wherever the handset is. The engine
    // must flag it for a phone call, and must say why it might be benign.
    const mailbox = 'carrier.user@example.edu';
    const baseline = buildBaseline(mailbox, normalHistory(mailbox));
    const onNetwork: RawLoginEvent = {
      mailbox, ts: at('2026-09-22T19:19:18Z'), eventName: 'login_success',
      ip: '203.0.113.25', asn: '13428', geo: 'US-IN', challenge: 'none', suspicious: false
    };
    const suspect: RawLoginEvent = {
      mailbox, ts: at('2026-09-22T19:21:41Z'), eventName: 'login_success',
      ip: '2600:387:15:2c17::1', asn: '7018', geo: 'US-TX',
      challenge: 'password device_prompt', suspicious: true
    };
    const r = assessRisk(suspect, baseline, [onNetwork, suspect]);
    expect(r.flag).toBe(true);
    expect(r.reasons.some((x) => /carrier geolocation/.test(x))).toBe(true);
  });

  it('threshold is a real boundary, not decoration', () => {
    expect(FLAG_THRESHOLD).toBeGreaterThan(0);
    const mailbox = 'x@example.edu';
    const quiet = assessRisk(
      { mailbox, ts: at('2026-09-22T13:00:00Z'), eventName: 'login_success',
        ip: '203.0.113.25', asn: '13428', geo: 'US-IN', challenge: 'none', suspicious: false },
      buildBaseline(mailbox, normalHistory(mailbox))
    );
    expect(quiet.score).toBeLessThan(FLAG_THRESHOLD);
  });
});

describe('network classification — consumer VPN is not hosting', () => {
  const mailbox = 'teacher@example.edu';

  /** Cloudflare WARP: AS13335, a network this user has not used before. */
  const warpEvent: RawLoginEvent = {
    mailbox,
    ts: at('2026-09-24T14:05:00Z'),
    eventName: 'login_success',
    ip: '104.28.51.9',
    asn: '13335',
    geo: 'US-IL',
    challenge: 'none',
    suspicious: false
  };

  it('flags WARP as hosting when RDAP is unavailable (the old behaviour)', () => {
    // Without the netblock owner, the ASN list is all there is, and it over-flags.
    // This is the fallback, and it must stay loud rather than silently forgiving.
    const r = assessRisk(warpEvent, buildBaseline(mailbox, normalHistory(mailbox)));
    expect(r.score).toBeGreaterThanOrEqual(FLAG_THRESHOLD);
    expect(r.reasons.some((x) => /hosting\/VPN infrastructure/.test(x))).toBe(true);
  });

  it('does NOT flag WARP once RDAP identifies it as a consumer relay', () => {
    // ~90 of 110 flags in the September backfill were this exact case.
    const r = assessRisk(warpEvent, buildBaseline(mailbox, normalHistory(mailbox)), [], {
      klass: 'anonymizer',
      org: 'Cloudflare WARP'
    });
    expect(r.flag).toBe(false);
    expect(r.score).toBeLessThan(FLAG_THRESHOLD);
    expect(r.reasons.some((x) => /hosting\/VPN infrastructure/.test(x))).toBe(false);
    expect(r.reasons.some((x) => /Consumer VPN or privacy relay/.test(x))).toBe(true);
  });

  it('still names the VPN in the reasons, so a human can see why it scored at all', () => {
    const r = assessRisk(warpEvent, buildBaseline(mailbox, normalHistory(mailbox)), [], {
      klass: 'anonymizer',
      org: 'Cloudflare WARP'
    });
    expect(r.reasons.join(' ')).toContain('Cloudflare WARP');
  });

  it('a VPN plus real evidence still clears the threshold', () => {
    // The point is to stop a VPN raising a flag BY ITSELF, not to make VPNs invisible.
    const r = assessRisk(
      { ...warpEvent, suspicious: true, challenge: 'password idv_preregistered_phone' },
      buildBaseline(mailbox, normalHistory(mailbox)),
      [],
      { klass: 'anonymizer', org: 'Cloudflare WARP' }
    );
    expect(r.flag).toBe(true);
  });

  it('a consumer ISP in the ASN list is not scored as hosting', () => {
    const r = assessRisk(warpEvent, buildBaseline(mailbox, normalHistory(mailbox)), [], {
      klass: 'residential',
      org: 'Comcast Cable Communications'
    });
    expect(r.reasons.some((x) => /hosting\/VPN infrastructure/.test(x))).toBe(false);
    expect(r.reasons.some((x) => /registered to a consumer ISP/.test(x))).toBe(true);
  });

  it('genuine attacker hosting is unaffected by the change', () => {
    // AS174 Cogent, the first confirmed takeover. RDAP classifies it as neither
    // residential nor a consumer relay, so the datacenter rule still applies in full.
    const r = assessRisk(
      { mailbox, ts: at('2026-09-13T19:18:46Z'), eventName: 'login_success',
        ip: '192.0.2.68', asn: '174', geo: 'US-NY',
        challenge: 'password idv_preregistered_phone', suspicious: true },
      buildBaseline(mailbox, normalHistory(mailbox)),
      [],
      { klass: 'unknown', org: 'Cogent Communications' }
    );
    expect(r.flag).toBe(true);
    expect(r.reasons.some((x) => /hosting\/VPN infrastructure/.test(x))).toBe(true);
  });
});

describe('district network — on site lowers risk, never raises it', () => {
  const mailbox = 'teacher@example.edu';
  const onSite: RawLoginEvent = {
    mailbox,
    ts: at('2026-09-24T14:05:00Z'),
    eventName: 'login_success',
    ip: '198.51.100.40',
    asn: '13428',
    geo: 'US-IN',
    challenge: 'none',
    suspicious: false
  };

  it('does not flag a new subnet inside the district range', () => {
    // A new /24 inside the district's own egress is a new VLAN or a new building.
    const r = assessRisk(onSite, buildBaseline(mailbox, normalHistory(mailbox)), [], {
      klass: 'unknown',
      onDistrictNetwork: true
    });
    expect(r.flag).toBe(false);
    expect(r.reasons.some((x) => /district network/.test(x))).toBe(true);
    expect(r.reasons.some((x) => /New network for this user/.test(x))).toBe(false);
  });

  it('still flags when Google calls it suspicious', () => {
    // "It came from inside" is exactly the wrong conclusion for a compromised district
    // machine or a malicious insider, so the strong signals are not suppressed.
    const r = assessRisk(
      { ...onSite, suspicious: true, challenge: 'password idv_preregistered_phone' },
      buildBaseline(mailbox, normalHistory(mailbox)),
      [],
      { klass: 'unknown', onDistrictNetwork: true }
    );
    expect(r.flag).toBe(true);
  });

  it('still surfaces a sensitive Gmail action from on site', () => {
    const r = assessRisk(
      { ...onSite, sensitive: 'Access sensitive Gmail action (e.g. filters without forwarding)' },
      buildBaseline(mailbox, normalHistory(mailbox)),
      [],
      { klass: 'unknown', onDistrictNetwork: true }
    );
    expect(r.reasons.some((x) => /Sensitive Gmail action/.test(x))).toBe(true);
  });

  it('is inert when the setting is not matched', () => {
    const r = assessRisk(onSite, buildBaseline(mailbox, normalHistory(mailbox)), [], {
      klass: 'unknown',
      onDistrictNetwork: false
    });
    expect(r.reasons.some((x) => /district network/.test(x))).toBe(false);
  });
});

describe('flag threshold is operator-tunable', () => {
  const mailbox = 'x@example.edu';
  const ev: RawLoginEvent = {
    mailbox, ts: at('2026-09-22T13:00:00Z'), eventName: 'login_success',
    ip: '198.51.100.7', asn: '99999', geo: 'US-CA', challenge: 'none', suspicious: false
  };

  it('honours a threshold passed from Settings', () => {
    const b = buildBaseline(mailbox, normalHistory(mailbox));
    const score = assessRisk(ev, b).score;
    // Sits above a threshold set below it, and below one set above it. The setting used
    // to be read by nothing at all — an admin changed it and got identical results.
    expect(assessRisk(ev, b, [], null, score).flag).toBe(true);
    expect(assessRisk(ev, b, [], null, score + 1).flag).toBe(false);
  });

  it('defaults to FLAG_THRESHOLD when not supplied', () => {
    const b = buildBaseline(mailbox, normalHistory(mailbox));
    expect(assessRisk(ev, b).flag).toBe(assessRisk(ev, b, [], null, FLAG_THRESHOLD).flag);
  });
});

describe('outside the home country — flagged on its own', () => {
  const mailbox = 'teacher@example.edu';
  const b = () => buildBaseline(mailbox, normalHistory(mailbox));
  const ev = (geo: string): RawLoginEvent => ({
    mailbox, ts: at('2026-09-29T03:10:00Z'), eventName: 'login_success',
    ip: '203.0.113.9', asn: '13428', geo, challenge: 'none', suspicious: false
  });

  it('flags a foreign sign-in with no other evidence', () => {
    const r = assessRisk(ev('NG-LA'), b());
    expect(r.flag).toBe(true);
    expect(r.reasons.join(' ')).toMatch(/OUTSIDE US \(NG-LA\)/);
  });

  it('does not flag an in-country region the user has not used', () => {
    // Consumer ISPs geolocate to the nearest metro hub, often next state. Not travel, not foreign.
    const r = assessRisk(ev('US-IL'), b());
    expect(r.reasons.join(' ')).not.toMatch(/OUTSIDE/);
  });

  it('is not suppressed by a VPN — it names the VPN instead', () => {
    const r = assessRisk(ev('NL-NH'), b(), [], { klass: 'anonymizer', org: 'Cloudflare WARP' });
    expect(r.flag).toBe(true);
    expect(r.reasons.join(' ')).toMatch(/through a VPN/);
  });

  it('honours additional home countries', () => {
    const r = assessRisk(ev('CA-ON'), b(), [], null, FLAG_THRESHOLD, ['US', 'CA']);
    expect(r.reasons.join(' ')).not.toMatch(/OUTSIDE/);
  });

  it('ignores a missing or malformed location rather than guessing', () => {
    expect(assessRisk({ ...ev(''), geo: null }, b()).reasons.join(' ')).not.toMatch(/OUTSIDE/);
  });
});
