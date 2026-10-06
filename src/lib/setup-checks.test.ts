import { describe, it, expect } from 'vitest';
import { extractDwdLink } from './setup-checks';

/**
 * Regression: GAM 7.x prints its own shortener (gam-shortn.appspot.com) for the domain-wide
 * delegation authorization, not the admin.google.com URL the wizard used to match. The
 * wizard showed the DWD failure with NO clickable link on every district running current
 * GAM. Both forms must be captured; the output shape below is GAM 7.48's verbatim (with an
 * invented mailbox).
 */
describe('extractDwdLink', () => {
  const modern = [
    'Domain-wide Delegation authentication:, User: alex@example.edu, Scope: 1',
    '  https://www.googleapis.com/auth/gmail.readonly                            FAIL',
    'Some scopes FAILED or should be DISABLED!',
    'To update authorization, please go to the following link in your browser:',
    '',
    '    https://gam-shortn.appspot.com/yqnmk3',
    '',
    'You will be directed to the Google Workspace admin console...'
  ].join('\n');

  const legacy = [
    'The service account is not authorized for all scopes. Please authorize at:',
    '  https://admin.google.com/ac/owl/domainwidedelegation?clientScopeToAdd=https%3A%2F%2Fmail.google.com%2F&clientIdToAdd=123456789&overwriteClientId=true',
    'then wait and retry.'
  ].join('\n');

  const allPass = [
    'Domain-wide Delegation authentication:, User: alex@example.edu, Scopes: 42',
    '  https://mail.google.com/   PASS (1/42)',
    'All scopes PASSED!'
  ].join('\n');

  it('captures the modern GAM shortener link', () => {
    expect(extractDwdLink(modern)).toBe('https://gam-shortn.appspot.com/yqnmk3');
  });

  it('still captures the legacy admin.google.com link', () => {
    expect(extractDwdLink(legacy)).toBe(
      'https://admin.google.com/ac/owl/domainwidedelegation?clientScopeToAdd=https%3A%2F%2Fmail.google.com%2F&clientIdToAdd=123456789&overwriteClientId=true'
    );
  });

  it('returns undefined when every scope already passed (no link to show)', () => {
    expect(extractDwdLink(allPass)).toBeUndefined();
  });

  it('does not capture trailing prose or whitespace', () => {
    const link = extractDwdLink(modern)!;
    expect(link.endsWith('yqnmk3')).toBe(true);
    expect(/\s/.test(link)).toBe(false);
  });
});
