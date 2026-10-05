/**
 * Time-box the PII tables that otherwise grow forever — login events (IPs/geo of staff and
 * minors), reviewed sign-in flags, full forwarded report bodies, and student VPN notices.
 *
 * Each period is independent and **0 means keep indefinitely** (that table is skipped), so an
 * existing install prunes nothing until an operator sets a policy — a destructive data policy
 * should be opt-in, not a surprise on upgrade.
 *
 * Evidence is preserved on purpose:
 *   - risk flags: only BENIGN (reviewed-and-cleared) rows are removed; NEW/INVESTIGATING and
 *     CONFIRMED_COMPROMISE stay whatever their age.
 *   - report bodies: the bulky forwarded email body is cleared but the report row and its
 *     metadata stay, and a CONFIRMED_PHISH report keeps its body.
 *   - student notices: only acted-on notices are removed; a QUEUED one awaiting review is kept.
 * The audit log is never touched here.
 */
import type { PrismaClient } from '@prisma/client';

export interface RetentionPolicy {
  loginEventDays: number;
  riskFlagBenignDays: number;
  reportBodyDays: number;
  studentNoticeDays: number;
}

export interface PruneResult {
  loginEvents: number;
  riskFlagsBenign: number;
  reportBodiesCleared: number;
  studentNotices: number;
  skipped: string[];
}

export function cutoff(days: number, now: number): Date {
  return new Date(now - days * 86_400_000);
}

export async function prunePii(
  prisma: PrismaClient,
  policy: RetentionPolicy,
  now: number = Date.now()
): Promise<PruneResult> {
  const r: PruneResult = {
    loginEvents: 0, riskFlagsBenign: 0, reportBodiesCleared: 0, studentNotices: 0, skipped: []
  };

  if (policy.loginEventDays > 0) {
    r.loginEvents = (
      await prisma.wardenLoginEvent.deleteMany({ where: { ts: { lt: cutoff(policy.loginEventDays, now) } } })
    ).count;
  } else r.skipped.push('loginEvents');

  if (policy.riskFlagBenignDays > 0) {
    r.riskFlagsBenign = (
      await prisma.wardenRiskFlag.deleteMany({
        where: { ts: { lt: cutoff(policy.riskFlagBenignDays, now) }, state: 'BENIGN' as never }
      })
    ).count;
  } else r.skipped.push('riskFlags');

  if (policy.reportBodyDays > 0) {
    r.reportBodiesCleared = (
      await prisma.wardenReport.updateMany({
        where: {
          createdAt: { lt: cutoff(policy.reportBodyDays, now) },
          bodyText: { not: null },
          NOT: { state: 'CONFIRMED_PHISH' as never }
        },
        data: { bodyText: null }
      })
    ).count;
  } else r.skipped.push('reportBodies');

  if (policy.studentNoticeDays > 0) {
    r.studentNotices = (
      await prisma.wardenStudentVpnNotice.deleteMany({
        where: { createdAt: { lt: cutoff(policy.studentNoticeDays, now) }, NOT: { state: 'QUEUED' as never } }
      })
    ).count;
  } else r.skipped.push('studentNotices');

  return r;
}

export function pruneSummary(r: PruneResult): string {
  const parts: string[] = [];
  if (!r.skipped.includes('loginEvents')) parts.push(`${r.loginEvents} login events`);
  if (!r.skipped.includes('riskFlags')) parts.push(`${r.riskFlagsBenign} benign flags`);
  if (!r.skipped.includes('reportBodies')) parts.push(`${r.reportBodiesCleared} report bodies cleared`);
  if (!r.skipped.includes('studentNotices')) parts.push(`${r.studentNotices} student notices`);
  return parts.length ? `pruned ${parts.join(', ')}` : 'retention disabled (all periods 0)';
}
