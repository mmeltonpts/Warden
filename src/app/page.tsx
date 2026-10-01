import { redirect } from 'next/navigation';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { hasAnyUser, isSetupComplete } from '@/lib/setup';

// Always per request: whether any account exists must never be decided at build time.
export const dynamic = 'force-dynamic';

export default async function Home() {
  if (!(await hasAnyUser(prisma))) redirect('/setup');
  const user = await currentUser();
  if (!user) redirect('/login');
  redirect(user.role === 'ADMIN' && !(await isSetupComplete(prisma)) ? '/setup' : '/risk');
}
