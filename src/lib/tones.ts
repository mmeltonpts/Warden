/**
 * Alert tones, synthesised with Web Audio — no sound files to ship, license or load.
 * Browser-only.
 */

export type Tone = 'alarm' | 'chime' | 'beep';

/** Returns how long the tone lasts, in seconds. */
export function playTone(ctx: AudioContext, tone: string, volume: number): number {
  const gain = ctx.createGain();
  gain.gain.value = Math.max(0, Math.min(1, volume / 100)) * 0.6;
  gain.connect(ctx.destination);
  const t0 = ctx.currentTime + 0.02;

  const note = (freq: number, start: number, dur: number, type: OscillatorType) => {
    const o = ctx.createOscillator();
    const env = ctx.createGain();
    o.type = type;
    o.frequency.value = freq;
    // Short attack and release, so notes do not click.
    env.gain.setValueAtTime(0, t0 + start);
    env.gain.linearRampToValueAtTime(1, t0 + start + 0.01);
    env.gain.setValueAtTime(1, t0 + start + dur - 0.03);
    env.gain.linearRampToValueAtTime(0, t0 + start + dur);
    o.connect(env).connect(gain);
    o.start(t0 + start);
    o.stop(t0 + start + dur + 0.02);
  };

  if (tone === 'chime') {
    [988, 784, 659].forEach((f, i) => note(f, i * 0.28, 0.5, 'sine'));
    return 1.1;
  }
  if (tone === 'beep') {
    [0, 0.25, 0.5].forEach((s) => note(1000, s, 0.15, 'square'));
    return 0.7;
  }
  // alarm: two-tone siren, eight half-notes alternating.
  for (let i = 0; i < 8; i++) note(i % 2 ? 660 : 880, i * 0.25, 0.24, 'square');
  return 2.0;
}
