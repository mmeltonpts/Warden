/**
 * Prisma client pinned to globalThis.
 *
 * Sentinel's rule: instrumentation and route handlers do not reliably share a module
 * instance in Next. A second PrismaClient silently opens a second connection pool.
 */
import { PrismaClient } from '@prisma/client';

const g = globalThis as unknown as { wardenPrisma?: PrismaClient };

export const prisma =
  g.wardenPrisma ??
  new PrismaClient({ log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'] });

if (process.env.NODE_ENV !== 'production') g.wardenPrisma = prisma;
