import { describe, it, expect } from 'vitest';
import { errText } from './errors';

describe('errText', () => {
  it('takes the message from a real Error', () => {
    expect(errText(new Error('smtp refused'))).toBe('smtp refused');
  });

  it('survives the value that broke the KnowBe4 sync', () => {
    // An object with no `message`. The old code did (e as Error).message.slice(0, 300),
    // which threw from inside the catch and replaced the real failure with
    // "Cannot read properties of undefined (reading 'slice')" for ten straight runs.
    expect(() => errText({ code: 'ETIMEDOUT' })).not.toThrow();
    expect(errText({ code: 'ETIMEDOUT' })).toContain('ETIMEDOUT');
  });

  it.each([
    ['a string', 'boom', 'boom'],
    ['null', null, 'null'],
    ['undefined', undefined, 'undefined'],
    ['a number', 42, '42']
  ])('handles %s', (_label, input, expected) => {
    expect(errText(input)).toBe(expected);
  });

  it('never throws on a circular object', () => {
    const a: Record<string, unknown> = { x: 1 };
    a.self = a;
    expect(() => errText(a)).not.toThrow();
    expect(errText(a).length).toBeGreaterThan(0);
  });

  it('never throws when toJSON itself throws', () => {
    const nasty = { toJSON() { throw new Error('nope'); } };
    expect(() => errText(nasty)).not.toThrow();
  });

  it('never throws on a throwing message getter', () => {
    const nasty = { get message(): string { throw new Error('nope'); } };
    expect(() => errText(nasty)).not.toThrow();
  });

  it('surfaces cause, where the actionable detail usually is', () => {
    // fetch rejects with a bare "fetch failed"; ECONNREFUSED lives on cause.
    const e = new Error('fetch failed', { cause: new Error('ECONNREFUSED 10.0.0.5:443') });
    expect(errText(e)).toContain('ECONNREFUSED');
  });

  it('does not repeat cause when it already appears in the message', () => {
    const e = new Error('ECONNREFUSED', { cause: new Error('ECONNREFUSED') });
    expect(errText(e)).toBe('ECONNREFUSED');
  });

  it('falls back to the name when the message is empty', () => {
    expect(errText(new TypeError(''))).toBe('TypeError');
  });

  it('truncates to the requested length', () => {
    expect(errText(new Error('x'.repeat(900)), 300)).toHaveLength(300);
    expect(errText(new Error('x'.repeat(900)), 500)).toHaveLength(500);
  });
});
