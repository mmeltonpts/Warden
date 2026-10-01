/**
 * Verify this host can actually drive GAM before an incident depends on it.
 *   sudo -u warden npx tsx scripts/gam-check.ts
 */
import { spawnSync } from 'node:child_process';
import { PrismaClient } from '@prisma/client';
import { getSettings } from '../src/lib/settings';

const prisma = new PrismaClient();

async function main() {
  const s = await getSettings(prisma);
  console.log(`gam path: ${s.gamPath}`);

  const v = spawnSync(s.gamPath, ['version'], { encoding: 'utf8' });
  if (v.error) {
    console.error(`  FAIL — cannot execute: ${v.error.message}`);
    process.exitCode = 1;
    return;
  }
  console.log(`  ${v.stdout.split('\n')[0]}`);

  const d = spawnSync(s.gamPath, ['info', 'domain'], { encoding: 'utf8', timeout: 60_000 });
  const ok = d.status === 0;
  console.log(`  domain access: ${ok ? 'OK' : 'FAIL'}`);
  if (!ok) {
    console.error((d.stderr || d.stdout || '').split('\n').slice(0, 5).join('\n'));
    process.exitCode = 1;
    return;
  }
  console.log(`  destructive ops: ${process.env.WARDEN_ALLOW_DESTRUCTIVE === '1' ? 'ENABLED' : 'disabled (sweeps refused)'}`);
}

main().finally(() => prisma.$disconnect());
