/**
 * Print a one-time code for claiming a fresh console at /setup.
 *
 *   sudo -u warden npx tsx scripts/setup-token.ts
 *
 * The installer runs this at the end. Run it again if the code expires (72 hours) or is
 * lost. Once an account exists the code is useless — /setup only accepts it while the
 * console has no users at all.
 */
import { PrismaClient } from '@prisma/client';
import { issueSetupToken, hasAnyUser } from '../src/lib/setup';

const prisma = new PrismaClient();

async function main() {
  if (await hasAnyUser(prisma)) {
    console.log('This console already has accounts — no setup code is needed. Sign in at /login.');
    console.log('Locked out? Create an admin with: sudo -u warden npx tsx scripts/seed-admin.ts you@your-domain');
    return;
  }
  const token = await issueSetupToken(prisma);
  console.log(token);
}

main().finally(() => prisma.$disconnect());
