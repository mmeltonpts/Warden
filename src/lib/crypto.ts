/**
 * Encryption for settings stored in the database.
 *
 * AES-256-GCM. The key is derived once from WARDEN_MASTER_KEY via scrypt and cached on
 * globalThis — scrypt is deliberately slow, and the settings row is read on most requests.
 *
 * Format:  enc:v1:<iv-b64>:<tag-b64>:<ciphertext-b64>
 *
 * The prefix is on purpose. A value that was written before encryption existed, or by a
 * hand-edited row, is obvious on sight and `decrypt()` returns it unchanged rather than
 * throwing — so a partially-migrated table still boots and can be re-saved to encrypt.
 *
 * GCM is authenticated: a tampered ciphertext fails to decrypt rather than silently
 * yielding garbage. That matters here because a settings value is a GAM path or a domain
 * name that gets handed to a subprocess.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

const PREFIX = 'enc:v1:';
type G = typeof globalThis & { wardenCryptoKey?: Buffer };
const g = globalThis as G;

function key(): Buffer {
  if (g.wardenCryptoKey) return g.wardenCryptoKey;
  const master = process.env.WARDEN_MASTER_KEY;
  if (!master || master.length < 16) {
    throw new Error(
      'WARDEN_MASTER_KEY is missing or too short. It is one of the three bootstrap ' +
        'secrets (with DATABASE_URL and SESSION_SECRET) and must exist before the ' +
        'settings table can be read. Generate with: openssl rand -hex 32'
    );
  }
  // Fixed salt: the master key is already high-entropy, and a per-value salt would mean
  // a scrypt derivation on every field read.
  g.wardenCryptoKey = scryptSync(master, 'warden-settings-v1', 32);
  return g.wardenCryptoKey;
}

export function isEncrypted(v: unknown): boolean {
  return typeof v === 'string' && v.startsWith(PREFIX);
}

export function encrypt(plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key(), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return (
    PREFIX +
    [iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':')
  );
}

/** Returns non-encrypted input unchanged, so a legacy row still works. */
export function decrypt(value: string): string {
  if (!isEncrypted(value)) return value;
  const [ivB64, tagB64, ctB64] = value.slice(PREFIX.length).split(':');
  if (!ivB64 || !tagB64 || !ctB64) throw new Error('malformed encrypted value');
  const d = createDecipheriv('aes-256-gcm', key(), Buffer.from(ivB64, 'base64'));
  d.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ctB64, 'base64')), d.final()]).toString('utf8');
}

/**
 * Fields whose VALUES are encrypted individually rather than the whole settings blob.
 * Whole-blob encryption would work, but per-field means a DBA reading the table can still
 * see which knobs exist without being able to read the sensitive ones.
 */
export const SENSITIVE_KEYS = new Set([
  'gamPath',
  'gamServiceAccountPath',
  'aiCommand',
  'smtpPassword',
  'webhookUrl',
  'reportingToken',
  'userEventsToken',
  // Was missing: marked sensitive in FIELDS, described as 'Encrypted at rest' in the UI, and
  // stored in plaintext. Matching is by leaf key NAME, so a new secret must be added here —
  // settings.test.ts now fails if any FIELDS entry marked sensitive is absent from this set.
  'abuseChAuthKey',
  'clientSecret'
]);

/**
 * Walks nested objects — `knowbe4.reportingToken` is two levels down, and a top-level-only
 * pass would leave it in plaintext while appearing to work.
 */
function walk(
  obj: Record<string, unknown>,
  fn: (key: string, value: string) => string | undefined
): Record<string, unknown> {
  const out: Record<string, unknown> = Array.isArray(obj) ? [...(obj as unknown[])] as never : { ...obj };
  for (const k of Object.keys(out)) {
    const v = out[k];
    if (v && typeof v === 'object') {
      out[k] = walk(v as Record<string, unknown>, fn);
    } else if (typeof v === 'string') {
      const next = fn(k, v);
      if (next !== undefined) out[k] = next;
    }
  }
  return out;
}

export function encryptFields<T extends Record<string, unknown>>(obj: T): T {
  return walk(obj, (k, v) =>
    SENSITIVE_KEYS.has(k) && v !== '' && !isEncrypted(v) ? encrypt(v) : undefined
  ) as T;
}

export function decryptFields<T extends Record<string, unknown>>(obj: T): T {
  return walk(obj, (_k, v) => {
    if (!isEncrypted(v)) return undefined;
    try {
      return decrypt(v);
    } catch {
      // Encrypted under a rotated master key. Surfaced in the UI as unreadable rather
      // than crashing every request that reads settings.
      return '';
    }
  }) as T;
}

/** Mask every sensitive value, at any depth, before anything reaches the browser. */
export function maskFields<T extends Record<string, unknown>>(obj: T): T {
  return walk(obj, (k, v) => (SENSITIVE_KEYS.has(k) ? maskSecret(v) : undefined)) as T;
}

/** Masked rendering for the Settings UI — never send a decrypted secret to the browser. */
export function maskSecret(v: string | undefined): string {
  if (!v) return '';
  if (v.length <= 8) return '••••••••';
  return `${v.slice(0, 3)}••••••••${v.slice(-3)}`;
}
