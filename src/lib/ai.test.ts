import { describe, it, expect } from 'vitest';
import { triageBody } from './ai';

// Shape of the 2026-09-30 eSign lure: heavy inline CSS, the Open link deep in the markup,
// then ~70 spacer divs and a stolen thread.
const css = 'font-variant-numeric: normal; font-variant-east-asian: normal; font-kerning: auto; font-optical-sizing: auto; font-feature-settings: normal; '.repeat(6);
const LINK = 'https://ctrk.klclick3.com/l/01M201N2J3BVJHVGC5C81QD6V3_1#&me56=bmljaG9sYXMuZ3JvbkBwb3J0YWdlLmsxMi5pbi51cw==';
const html =
  `<html><body><table style="${css}"><h1 style="${css}">nicholas.fowler@example.org have been assigned a task in the following:</h1>` +
  `<h3 style="${css}">nicholas.fowler</h3><span style="${css}">&bull; Pending eSign</span>`.repeat(4) +
  `<div><a href="${LINK}" role="button" style="${css}">Open</a></div></table></body>` +
  '<div style="height:30px;"></div>'.repeat(70) +
  '<html><body><p>KMP has quite a bit of labor into this&hellip; please tell us how to proceed?</p></body></html>';

describe('triageBody', () => {
  it('the raw HTML pushes the link past the 6,000-character budget — the bug', () => {
    expect(html.indexOf(LINK)).toBeGreaterThan(6000);
  });

  it('puts every extracted link first, inside the budget', () => {
    const b = triageBody(html, [LINK]);
    expect(b.slice(0, 6000)).toContain(LINK);
    expect(b.indexOf(LINK)).toBeLessThan(400);
  });

  it('keeps link targets inline so "Open" shows where it goes', () => {
    expect(triageBody(html, [])).toContain(`Open [${LINK}]`);
  });

  it('strips styling so the visible lure fits easily', () => {
    const b = triageBody(html, []);
    expect(b).not.toContain('font-variant');
    expect(b.slice(0, 6000)).toContain('Pending eSign');
    expect(b.slice(0, 6000)).toContain('have been assigned a task');
  });

  it('decodes entities', () => {
    expect(triageBody('<p>a&nbsp;b &amp; c&hellip;</p>', [])).toContain('a b & c');
  });
});
