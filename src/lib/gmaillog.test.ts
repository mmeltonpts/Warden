import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseGmailLog, scanGmailLogFile, flattenRow, splitCsv } from './gmaillog';

const P = 'parameters.1.messageValue.parameter';
// The rule record exactly as Google logged it for the 2026-09-29 BEC, trimmed.
const RULE = JSON.stringify([
  {
    policy_id: '3452778164781058',
    rule_id: '46',
    consequence: [{ action: '3', reason: 'Triggered by CONTENT_COMPLIANCE rule.', admin_quarantine_info: { admin_quarantine_id: '0' } }],
    string_match: [{ matched_string: 'Jane Superintendent' }],
    rule_name: 'Superintendent impersonation (EXTERNAL sender)'
  }
]);
const q = (s: string) => `"${s.replace(/"/g, '""')}"`;

const header = [
  'actor.email', 'id.time', 'ipAddress', 'parameters.1.name',
  `${P}.0.name`, `${P}.0.value`,
  `${P}.1.name`, `${P}.1.value`,
  `${P}.2.name`, `${P}.2.value`,
  `${P}.3.name`, `${P}.3.messageValue.parameter.0.name`, `${P}.3.messageValue.parameter.0.value`,
  `${P}.4.name`, `${P}.4.intValue`,
  `${P}.5.name`, `${P}.5.multiValue.0`, `${P}.5.multiValue.1`
];

const heldRow = [
  'pat.morgan@example.org', '2026-09-29T10:57:40Z', '192.0.2.107', 'message_info',
  'rfc2822_message_id', '<0f00ba11-0000-4000-8000-000000000001@lure-host.example>',
  'subject', 'Net 30',
  'flattened_triggered_rule_info', q(RULE),
  'source', 'from_header_address', 'reply@lure-host.example',
  'num_message_attachments', '2',
  'link_domain', 'lure-host.example', 'googleapis.com'
];

// Same message, delivered-leg row: no rule, and the columns SHIFT — subject moves to slot 0.
const plainRow = [
  'pat.morgan@example.org', '2026-09-29T10:57:38Z', '192.0.2.107', 'message_info',
  'subject', 'Net 30',
  'rfc2822_message_id', '<0f00ba11-0000-4000-8000-000000000001@lure-host.example>',
  '', '', '', '', '', '', '', '', '', ''
];

const csv = [header.join(','), heldRow.join(','), plainRow.join(',')].join('\n');

describe('gmail delivery log', () => {
  it('resolves positional columns to named paths', () => {
    const f = flattenRow(header, splitCsv(heldRow.join(',')));
    expect(f['message_info.subject']).toBe('Net 30');
    expect(f['message_info.source.from_header_address']).toBe('reply@lure-host.example');
  });

  it('reads the quarantine and the rule that made it', () => {
    const [held] = parseGmailLog(csv);
    expect(held.quarantined).toBe(true);
    expect(held.rules[0].name).toBe('Superintendent impersonation (EXTERNAL sender)');
    expect(held.rules[0].matched).toEqual(['Jane Superintendent']);
    expect(held.msgId).toBe('0f00ba11-0000-4000-8000-000000000001@lure-host.example');
    expect(held.recipient).toBe('pat.morgan@example.org');
    expect(held.sender).toBe('reply@lure-host.example');
    expect(held.attachments).toBe(2);
    expect(held.linkDomains).toContain('lure-host.example');
  });

  it('does not trust column positions — a shifted row still parses by name', () => {
    const [, plain] = parseGmailLog(csv);
    expect(plain.subject).toBe('Net 30');
    expect(plain.msgId).toMatch(/^0f00ba11/);
    expect(plain.quarantined).toBe(false);
  });

  it('streams a file and only fully parses rows containing the needle', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'gl-'));
    const file = path.join(dir, 'r.csv');
    writeFileSync(file, csv);
    const seen: string[] = [];
    const r = await scanGmailLogFile(file, 'admin_quarantine_info', (e) => { seen.push(e.msgId); });
    expect(r.rows).toBe(2);
    expect(r.matched).toBe(1);
    expect(seen).toHaveLength(1);
  });

  it('joins a record whose quoted subject contains a newline', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'gl-'));
    const file = path.join(dir, 'r.csv');
    const multi = heldRow.slice();
    multi[7] = q('Net 30\nURGENT');
    writeFileSync(file, [header.join(','), multi.join(',')].join('\n'));
    const got: string[] = [];
    await scanGmailLogFile(file, 'admin_quarantine_info', (e) => { got.push(e.subject ?? ''); });
    expect(got).toEqual(['Net 30\nURGENT']);
  });
});
