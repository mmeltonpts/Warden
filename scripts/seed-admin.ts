/**
 * Recovery: create an ADMIN from the host's shell. Normal installs create the first admin
 * in the browser at /setup; use this only if every admin is locked out.
 *
 * Password is generated, shown ONCE, and never stored in plaintext.
 *   sudo -u warden npx tsx scripts/seed-admin.ts you@your-domain.org
 */
import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const email = (process.argv[2] ?? '').trim().toLowerCase();
  if (!email.includes('@')) {
    console.error('usage: sudo -u warden npx tsx scripts/seed-admin.ts you@your-domain.org');
    process.exitCode = 1;
    return;
  }
  const existing = await prisma.wardenUser.findUnique({ where: { email } });
  if (existing) {
    console.log(`${email} already exists (role ${existing.role}) — no change made.`);
    return;
  }
  const password = randomBytes(12).toString('base64url');
  await prisma.wardenUser.create({
    data: {
      email,
      displayName: email.split('@')[0],
      passwordHash: await bcrypt.hash(password, 12),
      role: 'ADMIN'
    }
  });
  await prisma.wardenAudit.create({ data: { operator: 'host-shell', action: 'user_create', target: email, detail: 'role ADMIN via seed-admin.ts' } });
  console.log('\n  Warden admin created');
  console.log(`  email:    ${email}`);
  console.log(`  password: ${password}`);
  console.log('  Change it after first sign-in. This is the only time it is shown.\n');
}

main().finally(() => prisma.$disconnect());
