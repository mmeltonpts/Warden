import type { PrismaClient } from '@prisma/client';
import { falconClient, type FalconSettings } from './crowdstrike';
import { matchTool, splitList, type ToolRow } from './remote-tools';
import { errText } from './errors';

/**
 * Remote-access tool inventory, fetched in the background and stored as a snapshot.
 *
 * Fetching live on page load took 43 seconds — 1,885 records over 19 cursor pages of
 * Falcon's application inventory. Falcon only records usage to the hour, so an hourly
 * background pull loses nothing and makes the tab instant.
 */
export const SNAPSHOT_KEY = 'remote_tools_snapshot';
export const SNAPSHOT_MAX_AGE_MS = 60 * 60_000;

export interface ToolSnapshot {
  at: string;
  watchKey: string;
  rows: ToolRow[];
  error: string | null;
}

export async function readToolSnapshot(prisma: PrismaClient): Promise<ToolSnapshot | null> {
  const row = await prisma.wardenSetting.findUnique({ where: { key: SNAPSHOT_KEY } }).catch(() => null);
  if (!row) return null;
  try {
    return JSON.parse(row.value) as ToolSnapshot;
  } catch {
    return null;
  }
}

/** Refresh if older than an hour (or `force`). Never throws — a failure is stored and shown. */
export async function refreshToolSnapshot(
  prisma: PrismaClient,
  cfg: FalconSettings & { watchTools: string },
  force = false
): Promise<string> {
  const watch = splitList(cfg.watchTools);
  const watchKey = watch.join('|');
  const prev = await readToolSnapshot(prisma);
  if (!force && prev && prev.watchKey === watchKey && Date.now() - Date.parse(prev.at) < SNAPSHOT_MAX_AGE_MS) {
    return 'tools: fresh';
  }

  let snap: ToolSnapshot;
  try {
    const apps = await (await falconClient(cfg)).applications(watch);
    const rows: ToolRow[] = apps.map((a) => ({
      tool: matchTool(a.name, watch) ?? a.name,
      appName: a.name,
      version: a.version ?? null,
      hostname: a.host?.hostname ?? '?',
      lastUser: a.last_used_user_name ?? a.last_used_user_sid ?? null,
      lastUsedAt: a.last_used_timestamp ?? null,
      fileName: a.last_used_file_name ?? null
    }));
    // An install record with no use, next to a used record for the same tool on the same
    // PC, adds nothing. Indexed rather than nested-scanned: 1,885 rows squared is not free.
    const used = new Set(rows.filter((r) => r.lastUsedAt).map((r) => `${r.hostname}|${r.tool}`));
    snap = {
      at: new Date().toISOString(),
      watchKey,
      error: null,
      rows: rows.filter((r) => r.lastUsedAt || !used.has(`${r.hostname}|${r.tool}`))
    };
  } catch (e) {
    // Keep the last good rows and say the refresh failed, rather than blanking the tab.
    snap = { at: new Date().toISOString(), watchKey, rows: prev?.rows ?? [], error: errText(e, 200) };
  }

  await prisma.wardenSetting.upsert({
    where: { key: SNAPSHOT_KEY },
    create: { key: SNAPSHOT_KEY, value: JSON.stringify(snap), updatedBy: 'sync-falcon' },
    update: { value: JSON.stringify(snap), updatedBy: 'sync-falcon' }
  });
  return snap.error ? `tools: refresh FAILED (${snap.error})` : `tools: ${snap.rows.length} installs`;
}
