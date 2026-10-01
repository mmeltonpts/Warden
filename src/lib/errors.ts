/**
 * Turning a caught value into text, without the error handler itself throwing.
 *
 * `catch (e) { ... (e as Error).message.slice(0, 300) }` is wrong, and wrong in a way that
 * erases the evidence. `catch` receives `unknown`: a string, an object with no `message`,
 * null, or a rejected non-Error from a library. When `message` is undefined the `.slice`
 * throws from INSIDE the handler, so the new TypeError replaces the original failure and
 * propagates out of the function that was supposed to be reporting it.
 *
 * That is not hypothetical here. The KnowBe4 sync failed ten consecutive scheduled runs
 * and recorded:
 *
 *     Cannot read properties of undefined (reading 'slice')
 *
 * which says nothing whatsoever about KnowBe4. The real error — whatever KSAT or the
 * network actually did — was destroyed by the code trying to describe it.
 *
 * A handler must not be able to fail. This one cannot.
 */

/** Reading a property can itself throw — a getter on the caught object is still code. */
function peek(o: unknown, key: string): unknown {
  try {
    return (o as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/**
 * Best available text for a caught value. Never throws, always returns a string.
 *
 * The whole body is wrapped: a helper whose contract is "cannot fail" does not get to
 * assume its own cleverness is safe. Property reads, toJSON and String() are all code
 * supplied by whatever was thrown.
 */
export function errText(e: unknown, max = 300): string {
  try {
    let s = '';
    if (typeof e === 'string') {
      s = e;
    } else if (e === null || e === undefined) {
      s = String(e);
    } else if (typeof e === 'object') {
      // Covers Error, AggregateError, DOMException-likes, and plain-object rejections.
      const m = peek(e, 'message');
      if (typeof m === 'string' && m) {
        s = m;
      } else {
        const n = peek(e, 'name');
        if (typeof n === 'string' && n) {
          s = n;
        } else {
          try {
            s = JSON.stringify(e) ?? '';
          } catch {
            s = ''; // circular, or a throwing toJSON
          }
        }
      }
    } else {
      s = String(e);
    }
    if (!s) s = Object.prototype.toString.call(e);

    // `cause` usually carries the actionable detail: fetch rejects with a bare
    // "fetch failed" and hides ECONNREFUSED underneath it.
    const cause = peek(e, 'cause');
    if (cause !== undefined && cause !== null && s.length < max) {
      const cm = typeof cause === 'string' ? cause : peek(cause, 'message');
      if (typeof cm === 'string' && cm && !s.includes(cm)) s = `${s} (cause: ${cm})`;
    }
    return s.slice(0, max);
  } catch {
    return 'unprintable error';
  }
}
