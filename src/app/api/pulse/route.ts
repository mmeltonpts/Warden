/**
 * Polled by every open console for the alert sound. Returns only what qualifies under
 * Settings → Sounds, from the last 24 hours, so an old backlog never starts a siren.
 */
import { NextResponse } from 'next/server';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { severitySet, qualifies, soundLimits, type PulseItem } from '@/lib/pulse';

export const dynamic = 'force-dynamic';

export async function GET() {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });

  const s = await getSettings(prisma);
  const lim = soundLimits(s.sound);
  if (!s.sound.enabled) return NextResponse.json({ enabled: false, ...lim, items: [] });

  const since = new Date(Date.now() - 24 * 3600_000);
  const items: PulseItem[] = [];

  const wantAlerts = severitySet(s.sound.alertSeverities);
  if (wantAlerts.size) {
    const rows = await prisma.wardenAlert.findMany({
      where: { createTime: { gte: since } },
      orderBy: { createTime: 'desc' },
      take: 200,
      select: { alertId: true, type: true, severity: true, createTime: true, state: true, email: true }
    });
    for (const r of rows) {
      if (!qualifies(r.severity, wantAlerts)) continue;
      items.push({
        id: `a:${r.alertId}`,
        source: 'alert',
        title: `${r.severity} — ${r.type}${r.email ? ` (${r.email})` : ''}`,
        href: `/alerts/${encodeURIComponent(r.alertId)}`,
        at: r.createTime.toISOString(),
        open: r.state === 'NEW'
      });
    }
  }

  const wantFalcon = severitySet(s.sound.falconSeverities);
  if (s.sound.falcon && s.crowdstrike.enabled && wantFalcon.size) {
    const rows = await prisma.wardenEdrAlert.findMany({
      where: { createdAt: { gte: since } },
      orderBy: { createdAt: 'desc' },
      take: 200,
      select: { compositeId: true, severityName: true, displayName: true, name: true, hostname: true, createdAt: true, status: true, blocked: true }
    });
    for (const r of rows) {
      if (!qualifies(r.severityName, wantFalcon)) continue;
      items.push({
        id: `f:${r.compositeId}`,
        source: 'falcon',
        title: `Falcon ${r.severityName} — ${r.displayName ?? r.name ?? 'detection'}${r.hostname ? ` on ${r.hostname}` : ''}${r.blocked ? ' (blocked)' : ' (NOT blocked)'}`,
        href: `/edr?tab=detections${r.hostname ? `&host=${encodeURIComponent(r.hostname)}` : ''}`,
        at: r.createdAt.toISOString(),
        open: r.status === 'new' || r.status === 'reopened'
      });
    }
  }

  items.sort((a, b) => b.at.localeCompare(a.at));
  return NextResponse.json({ enabled: true, tone: s.sound.tone, ...lim, items: items.slice(0, 50) });
}
