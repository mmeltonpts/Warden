import { describe, it, expect } from 'vitest';
import { summarizeSent, isBlast, blastReasons } from './exfil';

const DOMAINS = ['example.edu', 'student.example.edu'];

describe('summarizeSent', () => {
  const csv = [
    'User,To,Cc,Date',
    'a@example.edu,"v1@gmail.com, v2@outside.test",colleague@example.edu,2026-10-05',
    'a@example.edu,v3@outside.test,,2026-10-05',
    'a@example.edu,colleague@example.edu,,2026-10-05'
  ].join('\n');

  it('counts messages and distinct recipients, splitting external from internal', () => {
    const s = summarizeSent(csv, DOMAINS);
    expect(s.messages).toBe(3);
    expect(new Set(s.recipients)).toEqual(
      new Set(['v1@gmail.com', 'v2@outside.test', 'colleague@example.edu', 'v3@outside.test'])
    );
    expect(new Set(s.external)).toEqual(new Set(['v1@gmail.com', 'v2@outside.test', 'v3@outside.test']));
  });

  it('is zero for an empty or header-only CSV', () => {
    expect(summarizeSent('', DOMAINS)).toEqual({ messages: 0, recipients: [], external: [] });
    expect(summarizeSent('User,To,Cc', DOMAINS)).toEqual({ messages: 0, recipients: [], external: [] });
  });
});

describe('isBlast', () => {
  const t = { maxMessages: 50, maxExternal: 25 };
  it('fires on a high message count', () => {
    expect(isBlast({ messages: 60, recipients: [], external: [] }, t)).toBe(true);
  });
  it('fires on many distinct external recipients even with few messages', () => {
    const external = Array.from({ length: 30 }, (_, i) => `v${i}@outside.test`);
    expect(isBlast({ messages: 3, recipients: external, external }, t)).toBe(true);
  });
  it('does not fire on ordinary sending', () => {
    expect(isBlast({ messages: 5, recipients: ['a@b.test'], external: ['a@b.test'] }, t)).toBe(false);
  });
});

describe('blastReasons', () => {
  it('names the volume, the prior flag, and sample external recipients', () => {
    const r = blastReasons(
      { messages: 80, recipients: ['x@o.test', 'y@o.test'], external: ['x@o.test', 'y@o.test'] },
      6,
      'new mail-capable OAuth grant'
    );
    const text = r.join(' ');
    expect(text).toMatch(/Sent 80 messages/);
    expect(text).toMatch(/new mail-capable OAuth grant/);
    expect(text).toMatch(/x@o\.test/);
  });
});
