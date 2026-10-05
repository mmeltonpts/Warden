import { describe, it, expect, vi } from 'vitest';
import { prunePii, pruneSummary, cutoff, type RetentionPolicy } from './retention';

const NOW = Date.parse('2026-10-05T00:00:00Z');

function mockPrisma() {
  const calls: Record<string, any[]> = {};
  const rec = (name: string, count: number) =>
    vi.fn(async (arg: any) => { (calls[name] ??= []).push(arg); return { count }; });
  const prisma = {
    wardenLoginEvent: { deleteMany: rec('loginDelete', 3) },
    wardenRiskFlag: { deleteMany: rec('flagDelete', 2) },
    wardenReport: { updateMany: rec('reportUpdate', 5) },
    wardenStudentVpnNotice: { deleteMany: rec('noticeDelete', 1) }
  } as any;
  return { prisma, calls };
}

describe('prunePii', () => {
  it('skips every table when all periods are 0 (opt-in) and makes no calls', async () => {
    const { prisma, calls } = mockPrisma();
    const policy: RetentionPolicy = { loginEventDays: 0, riskFlagBenignDays: 0, reportBodyDays: 0, studentNoticeDays: 0 };
    const r = await prunePii(prisma, policy, NOW);
    expect(Object.keys(calls)).toHaveLength(0);
    expect(r.skipped.sort()).toEqual(['loginEvents', 'reportBodies', 'riskFlags', 'studentNotices']);
    expect(pruneSummary(r)).toMatch(/disabled/);
  });

  it('prunes only what is enabled, with evidence-preserving filters', async () => {
    const { prisma, calls } = mockPrisma();
    const policy: RetentionPolicy = { loginEventDays: 180, riskFlagBenignDays: 365, reportBodyDays: 365, studentNoticeDays: 0 };
    const r = await prunePii(prisma, policy, NOW);

    // login events: purely age-based
    expect(calls.loginDelete[0].where.ts.lt).toEqual(cutoff(180, NOW));
    // risk flags: BENIGN only — confirmed/open flags are evidence
    expect(calls.flagDelete[0].where.state).toBe('BENIGN');
    expect(calls.flagDelete[0].where.ts.lt).toEqual(cutoff(365, NOW));
    // report bodies: cleared (not deleted), never for CONFIRMED_PHISH
    expect(calls.reportUpdate[0].data).toEqual({ bodyText: null });
    expect(calls.reportUpdate[0].where.NOT.state).toBe('CONFIRMED_PHISH');
    // student notices disabled -> no call
    expect(calls.noticeDelete).toBeUndefined();

    expect(r.loginEvents).toBe(3);
    expect(r.riskFlagsBenign).toBe(2);
    expect(r.reportBodiesCleared).toBe(5);
    expect(r.skipped).toEqual(['studentNotices']);
    expect(pruneSummary(r)).toBe('pruned 3 login events, 2 benign flags, 5 report bodies cleared');
  });

  it('keeps QUEUED student notices (pending review) when pruning notices', async () => {
    const { prisma, calls } = mockPrisma();
    await prunePii(prisma, { loginEventDays: 0, riskFlagBenignDays: 0, reportBodyDays: 0, studentNoticeDays: 90 }, NOW);
    expect(calls.noticeDelete[0].where.NOT.state).toBe('QUEUED');
    expect(calls.noticeDelete[0].where.createdAt.lt).toEqual(cutoff(90, NOW));
  });
});
