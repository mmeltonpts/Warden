import { describe, it, expect } from 'vitest';
import {
  reportQuery,
  unwrapRedirect,
  extractPayloadHosts,
  campaignKey,
  isKnownGood,
  stripSubjectTags
} from './reports';

/**
 * Regression: `to:` does not match a bare domain.
 *
 * `to:phisher.knowbe4.com` returned ZERO against 504 messages provably addressed to
 * `a42a9d34-…@phisher.knowbe4.com`. The whole report backfill silently found nothing and
 * reported "no reports found", which reads as success.
 */
describe('reportQuery', () => {
  it('uses a free-text term for a bare domain, not to:', () => {
    const q = reportQuery(['phisher.knowbe4.com'], 180);
    expect(q).toContain('"phisher.knowbe4.com"');
    expect(q).not.toContain('to:phisher.knowbe4.com');
  });

  it('still uses to: for a real address', () => {
    const q = reportQuery(['phishing@example.edu'], 7);
    expect(q).toContain('to:phishing@example.edu');
  });

  it('mixes both forms and keeps the lookback', () => {
    const q = reportQuery(['phishing@example.edu', 'phisher.knowbe4.com'], 30);
    expect(q).toBe(
      '(to:phishing@example.edu OR "phisher.knowbe4.com") in:anywhere newer_than:30d'
    );
  });
});

/**
 * Regression: a payload behind `google.com/url?q=` was invisible to a filter that excluded
 * "google", and a verification reported clean while real phish survived.
 */
describe('payload extraction', () => {
  it('unwraps the Google open redirect', () => {
    const wrapped = 'https://www.google.com/url?q=https%3A%2F%2Fdownloaddocument.tech%2Fx&sa=D';
    expect(unwrapRedirect(wrapped)).toBe('https://downloaddocument.tech/x');
  });

  it('finds a payload host hidden behind that redirect', () => {
    const body = 'Click here: https://www.google.com/url?q=https%3A%2F%2Fdownloaddocument.tech%2Fx';
    expect(extractPayloadHosts(body)).toContain('downloaddocument.tech');
  });

  it('drops reporting-chain and legitimate infrastructure hosts', () => {
    const body = 'https://mail.google.com/a https://example.org/b https://www.example.org/c https://evil.example/d';
    const hosts = extractPayloadHosts(body, ['example.org']);
    expect(hosts).toContain('evil.example');
    expect(hosts).not.toContain('mail.google.com');
    expect(hosts).not.toContain('example.org');
    expect(hosts).not.toContain('www.example.org');
  });

  it('only ignores the district domains it is told about', () => {
    // The district's own domain comes from Settings; a build must not know any district.
    const hosts = extractPayloadHosts('https://example.org/b', []);
    expect(hosts).toContain('example.org');
    // A look-alike that merely ends in the same letters is NOT the district.
    expect(extractPayloadHosts('https://notexample.org/x', ['example.org'])).toContain('notexample.org');
  });

  it('leaves a plain URL alone', () => {
    expect(unwrapRedirect('https://example.org/a?b=c')).toBe('https://example.org/a?b=c');
  });
});

/**
 * The attacker rotated nine sender accounts against one payload host. Keying campaigns on
 * sender would have reported nine incidents instead of one.
 */
describe('campaignKey', () => {
  it('prefers the payload host over the sender', () => {
    const k = campaignKey({
      originalSender: 'a@partner.example',
      originalSubject: 'Document',
      payloadHosts: ['downloaddocument.tech']
    });
    expect(k).toBe('host:downloaddocument.tech');
  });

  it('groups two different senders sharing a payload', () => {
    const a = campaignKey({ originalSender: 'a@x.org', payloadHosts: ['bad.tech'] });
    const b = campaignKey({ originalSender: 'b@y.org', payloadHosts: ['bad.tech'] });
    expect(a).toBe(b);
  });

  it('falls back to a normalised subject when there is no payload host', () => {
    const a = campaignKey({ originalSubject: 'Re: [External Sender] Revised Agreement', payloadHosts: [] });
    const b = campaignKey({ originalSubject: 'Revised Agreement', payloadHosts: [] });
    expect(a).toBe(b);
  });
});

/** Suppression must be visible and reversible, never a silent drop. */
describe('isKnownGood', () => {
  const list = ['no-reply@vendor.example', 'Example District Background Check'];

  it('suppresses on sender', () => {
    const r = isKnownGood({ originalSender: 'no-reply@vendor.example', payloadHosts: [] }, list);
    expect(r.suppressed).toBe(true);
    expect(r.matched).toBe('no-reply@vendor.example');
  });

  it('suppresses on a subject substring', () => {
    const r = isKnownGood(
      { originalSubject: '[External Sender] Example District Background Check Expires Soon', payloadHosts: [] },
      list
    );
    expect(r.suppressed).toBe(true);
  });

  it('does not suppress an unrelated report', () => {
    const r = isKnownGood({ originalSender: 'attacker@evil.example', payloadHosts: [] }, list);
    expect(r.suppressed).toBe(false);
  });
});

/**
 * Regression: a new gateway tag must not split an existing campaign.
 *
 * The day a district switches on a content-compliance rule that prepends something like
 * `[DISTRICT CONTACT FORM]`, previously-tagged and newly-tagged copies of the same notice would
 * stop grouping together and the count on the Reports page would silently halve.
 */
describe('stripSubjectTags', () => {
  it('removes a single gateway tag', () => {
    expect(stripSubjectTags('[External Sender] New response(s)')).toBe('New response(s)');
  });

  it('removes several stacked tags', () => {
    expect(stripSubjectTags('[DISTRICT CONTACT FORM] [External Sender] New response(s)')).toBe(
      'New response(s)'
    );
  });

  it('leaves an untagged subject alone', () => {
    expect(stripSubjectTags('Revised Agreement')).toBe('Revised Agreement');
  });

  it('groups tagged and untagged copies of one campaign together', () => {
    const tagged = campaignKey({
      originalSubject: '[DISTRICT CONTACT FORM] [External Sender] New response(s) - Contact A, Teacher',
      payloadHosts: []
    });
    const untagged = campaignKey({
      originalSubject: '[External Sender] New response(s) - Contact A, Teacher',
      payloadHosts: []
    });
    expect(tagged).toBe(untagged);
  });
});
