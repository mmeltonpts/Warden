/**
 * First-run setup state.
 *
 * A fresh install has no users and no settings. The first person to load the console is
 * walked through claiming it and then through every settings section in order. Until that
 * is finished, the scheduler runs nothing — an unconfigured install must never hand an
 * empty domain to GAM.
 *
 * CLAIMING needs a one-time code that the installer prints on the host's terminal. Without
 * it, whoever on the network reaches a new console first would become its ADMIN — and this
 * console can trash mail in every mailbox in the domain. Possession of the code proves
 * possession of the host.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';

const TOKEN_KEY = 'setup_token';
const COMPLETE_KEY = 'setup_complete';
const PROGRESS_KEY = 'setup_progress';
const TOKEN_HOURS = 72;

const sha = (s: string) => createHash('sha256').update(s.trim()).digest();

export async function isSetupComplete(prisma: PrismaClient): Promise<boolean> {
  return Boolean(await prisma.wardenSetting.findUnique({ where: { key: COMPLETE_KEY } }));
}

export async function hasAnyUser(prisma: PrismaClient): Promise<boolean> {
  return (await prisma.wardenUser.count()) > 0;
}

/** Issue a new claim code. Only the hash is stored; the code is shown once on the host. */
export async function issueSetupToken(prisma: PrismaClient): Promise<string> {
  const token = randomBytes(9).toString('base64url'); // 12 chars, ~72 bits
  const value = JSON.stringify({
    hash: sha(token).toString('hex'),
    expires: new Date(Date.now() + TOKEN_HOURS * 3600_000).toISOString()
  });
  await prisma.wardenSetting.upsert({
    where: { key: TOKEN_KEY },
    create: { key: TOKEN_KEY, value, updatedBy: 'installer' },
    update: { value, updatedBy: 'installer' }
  });
  return token;
}

/** True once, for the right unexpired code. Deletes it on success. */
export async function consumeSetupToken(prisma: PrismaClient, token: string): Promise<boolean> {
  const row = await prisma.wardenSetting.findUnique({ where: { key: TOKEN_KEY } });
  if (!row) return false;
  try {
    const { hash, expires } = JSON.parse(row.value) as { hash: string; expires: string };
    if (new Date(expires) < new Date()) return false;
    const want = Buffer.from(hash, 'hex');
    const got = sha(token);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return false;
  } catch {
    return false;
  }
  await prisma.wardenSetting.delete({ where: { key: TOKEN_KEY } }).catch(() => undefined);
  return true;
}

export async function setupProgress(prisma: PrismaClient): Promise<Record<string, 'saved' | 'skipped'>> {
  const row = await prisma.wardenSetting.findUnique({ where: { key: PROGRESS_KEY } });
  try {
    return row ? (JSON.parse(row.value) as Record<string, 'saved' | 'skipped'>) : {};
  } catch {
    return {};
  }
}

export async function markStep(prisma: PrismaClient, step: string, state: 'saved' | 'skipped', by: string) {
  const cur = await setupProgress(prisma);
  cur[step] = state;
  const value = JSON.stringify(cur);
  await prisma.wardenSetting.upsert({
    where: { key: PROGRESS_KEY },
    create: { key: PROGRESS_KEY, value, updatedBy: by },
    update: { value, updatedBy: by }
  });
}

export async function completeSetup(prisma: PrismaClient, by: string) {
  await prisma.wardenSetting.upsert({
    where: { key: COMPLETE_KEY },
    create: { key: COMPLETE_KEY, value: new Date().toISOString(), updatedBy: by },
    update: { value: new Date().toISOString(), updatedBy: by }
  });
  await prisma.wardenAudit.create({ data: { operator: by, action: 'setup_complete', detail: 'first-run setup finished' } });
}
