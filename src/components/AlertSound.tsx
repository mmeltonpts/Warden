'use client';

import { useEffect, useRef, useState } from 'react';
import { Volume2, VolumeX, X } from 'lucide-react';
import { playTone } from '@/lib/tones';
import type { PulseItem } from '@/lib/pulse';

/**
 * The audible alarm. Mounted on every page for signed-in users.
 *
 * Polls /api/pulse, and when a qualifying alert appears that this browser has not seen,
 * plays the configured tone and shows a banner linking to it. Seen IDs are kept in
 * localStorage so a page reload does not re-sound old alerts; the first ever poll in a
 * browser records what already exists without sounding, so opening the console onto an
 * existing backlog does not start a siren.
 *
 * Mute is per browser (the speaker button), on purpose: one person silencing their laptop
 * must not silence the console on the wall screen.
 */
const SEEN_KEY = 'warden.sound.seen';
const MUTE_KEY = 'warden.sound.muted';

function load<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
function save(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* private mode or storage blocked: sound still works, it just may repeat after reload */
  }
}

type Pulse = { enabled: boolean; tone?: string; volume: number; pollSeconds: number; repeatSeconds: number; items: PulseItem[] };

export function AlertSound() {
  const [enabled, setEnabled] = useState(false);
  const [muted, setMuted] = useState(false);
  const [fresh, setFresh] = useState<PulseItem[]>([]);
  const [blocked, setBlocked] = useState(false);
  const ctxRef = useRef<AudioContext | null>(null);
  const lastPlayed = useRef(0);

  useEffect(() => setMuted(load(MUTE_KEY, false)), []);

  // Browsers only allow audio after a user gesture. Unlock on the first click or key.
  useEffect(() => {
    const unlock = () => {
      try {
        ctxRef.current ??= new AudioContext();
        void ctxRef.current.resume().then(() => setBlocked(false));
      } catch {
        /* no Web Audio: the banner still shows */
      }
    };
    window.addEventListener('pointerdown', unlock);
    window.addEventListener('keydown', unlock);
    return () => {
      window.removeEventListener('pointerdown', unlock);
      window.removeEventListener('keydown', unlock);
    };
  }, []);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const sound = (p: Pulse) => {
      if (load(MUTE_KEY, false)) return;
      try {
        ctxRef.current ??= new AudioContext();
        if (ctxRef.current.state !== 'running') {
          setBlocked(true);
          return;
        }
        playTone(ctxRef.current, p.tone ?? 'alarm', p.volume);
        lastPlayed.current = Date.now();
      } catch {
        setBlocked(true);
      }
    };

    const tick = async () => {
      let next = 30;
      try {
        const r = await fetch('/api/pulse', { cache: 'no-store' });
        if (r.ok) {
          const p = (await r.json()) as Pulse;
          next = p.pollSeconds || 30;
          setEnabled(p.enabled);
          if (p.enabled) {
            const stored = load<string[] | null>(SEEN_KEY, null);
            const seen = new Set(stored ?? []);
            const unseen = p.items.filter((i) => !seen.has(i.id));
            if (stored === null) {
              // First time in this browser: learn the backlog silently.
            } else if (unseen.length) {
              setFresh((cur) => [...unseen, ...cur].slice(0, 8));
              sound(p);
            } else if (
              p.repeatSeconds > 0 &&
              p.items.some((i) => i.open) &&
              Date.now() - lastPlayed.current >= p.repeatSeconds * 1000
            ) {
              sound(p);
            }
            for (const i of p.items) seen.add(i.id);
            save(SEEN_KEY, [...seen].slice(-500));
          }
        }
      } catch {
        /* server unreachable: try again next round */
      }
      if (!stop) timer = setTimeout(tick, next * 1000);
    };

    void tick();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  if (!enabled) return null;

  return (
    <>
      {fresh.length > 0 && (
        <div
          role="alert"
          className="fixed right-4 top-4 z-50 w-96 max-w-[calc(100vw-2rem)] rounded border p-3 text-sm shadow-lg"
          style={{ background: 'rgb(var(--danger))', color: '#fff' }}
        >
          <div className="mb-1 flex items-center justify-between font-semibold">
            <span>Critical alert{fresh.length > 1 ? `s (${fresh.length})` : ''}</span>
            <button aria-label="Dismiss" onClick={() => setFresh([])}><X size={16} /></button>
          </div>
          <ul className="space-y-1">
            {fresh.map((i) => (
              <li key={i.id}>
                <a href={i.href} className="underline">{i.title}</a>
              </li>
            ))}
          </ul>
          {blocked && !muted && (
            <p className="mt-2 text-xs opacity-90">The browser blocked the sound — click anywhere on the page once to allow it.</p>
          )}
        </div>
      )}
      <button
        onClick={() => {
          const m = !muted;
          setMuted(m);
          save(MUTE_KEY, m);
        }}
        title={muted ? 'Alert sound is muted in this browser — click to unmute' : 'Alert sound is on — click to mute in this browser'}
        className="fixed bottom-4 right-4 z-40 rounded-full border bg-bg-elevated p-2 text-text-muted shadow"
      >
        {muted ? <VolumeX size={16} /> : <Volume2 size={16} />}
      </button>
    </>
  );
}

/** Settings → Sounds: hear the tone at the saved volume. Clicking it is the user gesture. */
export function TestSoundButton({ tone, volume }: { tone: string; volume: number }) {
  return (
    <button
      type="button"
      className="btn text-xs"
      onClick={() => {
        try {
          const ctx = new AudioContext();
          void ctx.resume().then(() => {
            const secs = playTone(ctx, tone, volume);
            setTimeout(() => void ctx.close(), (secs + 0.5) * 1000);
          });
        } catch {
          alert('This browser cannot play Web Audio.');
        }
      }}
    >
      Test sound
    </button>
  );
}
