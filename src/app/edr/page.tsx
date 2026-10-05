import { redirect } from 'next/navigation';
import { fmtTs } from '@/lib/time';
import Link from 'next/link';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings } from '@/lib/settings';
import { freshnessFor } from '@/lib/freshness';
import { IngestStatus } from '@/components/IngestStatus';
import { falconClient, falconHostLink } from '@/lib/crowdstrike';
import { classify, isServiceUser, splitList, type ToolRow } from '@/lib/remote-tools';
import { readToolSnapshot } from '@/lib/remote-tools-sync';
import { Laptop, ShieldAlert } from 'lucide-react';

export const dynamic = 'force-dynamic';

const SEV_PILL = (n: number) =>
  n >= 90 ? 'pill-critical' : n >= 70 ? 'pill-critical' : n >= 50 ? 'pill-high' : n >= 20 ? 'pill-medium' : 'pill-muted';

/**
 * Endpoint detections from CrowdStrike Falcon.
 *
 * Built after a rogue ScreenConnect client ran DETECTED-ONLY on three staff PCs from 9/28 to
 * 10/1, relaying through an indicator from the September phishing campaign, with OverWatch
 * leads unopened. Everything needed to see it was in Falcon; nothing put it in front of a
 * person. So this page leads with one question: what ran, where, and is that machine
 * contained yet.
 */
export default async function EdrPage({
  searchParams
}: {
  searchParams: Promise<{ view?: string; host?: string; tab?: string; tool?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  if (user.role === 'ANALYST') {
    return <div className="card text-sm">Endpoint detections require the RESPONDER or ADMIN role.</div>;
  }
  const { view = 'open', host, tab: tabParam, tool: toolParam } = await searchParams;
  // Three jobs, three tabs. As one page it was a mile long and made a live Falcon inventory
  // call on every load; now each tab only does its own work. A host filter implies the
  // detections tab, since that is what a host link is for.
  const tab = tabParam === 'tools' || tabParam === 'detections' ? tabParam : host ? 'detections' : 'action';

  const s = await getSettings(prisma);
  const fresh = await freshnessFor(prisma, 'falcon', s.schedule.falconMinutes ?? 5);

  if (!s.crowdstrike.enabled) {
    return (
      <div className="max-w-3xl space-y-3">
        <h1 className="text-lg font-semibold">Endpoint detections</h1>
        <div className="card text-sm">
          CrowdStrike is not enabled. Turn it on in{' '}
          <a className="underline" href="/settings?tab=CrowdStrike">Settings → CrowdStrike</a> and use
          Test connection.
        </div>
      </div>
    );
  }

  const since14 = new Date(Date.now() - 14 * 86_400_000);
  const open = { status: { in: ['new', 'in_progress', 'reopened'] } };
  const where = {
    ...(view === 'open' ? open : view === 'ran' ? { ...open, blocked: false } : {}),
    ...(host ? { hostname: host } : {})
  };

  /**
   * Hosts where something RAN (not blocked) at high/critical, or touched a known indicator,
   * or drew an OverWatch lead, in the last two weeks — with containment read live. The red
   * rows here are the ones somebody should be on right now.
   */
  const hot = await prisma.wardenEdrAlert.groupBy({
    by: ['hostname'],
    where: {
      createdAt: { gte: since14 },
      hostname: { not: null },
      OR: [{ blocked: false, severity: { gte: 70 } }, { iocHit: { not: null } }, { product: 'overwatch' }]
    },
    _count: { _all: true },
    _max: { createdAt: true, severity: true }
  });
  let containment = new Map<string, { status: string; lastSeen: string | null; deviceId: string | null }>();
  let containmentError: string | null = null;
  if (hot.length && tab === 'action') {
    try {
      const fc = await falconClient(s.crowdstrike);
      containment = await fc.devices(hot.slice(0, 20).map((h) => h.hostname!));
    } catch (e) {
      containmentError = String((e as Error).message ?? e).slice(0, 200);
    }
  }
  const hotRows = await Promise.all(
    hot
      .sort((a, b) => +(b._max.createdAt ?? 0) - +(a._max.createdAt ?? 0))
      .map(async (h) => {
        const users = await prisma.wardenEdrAlert.findMany({
          where: { hostname: h.hostname, mailbox: { not: null } },
          select: { mailbox: true },
          distinct: ['mailbox'],
          take: 3
        });
        const ioc = await prisma.wardenEdrAlert.findFirst({
          where: { hostname: h.hostname, iocHit: { not: null } },
          select: { iocHit: true }
        });
        return { ...h, users: users.map((u) => u.mailbox!), ioc: ioc?.iocHit ?? null };
      })
  );

  const [rows, total, ranCount, openCount] = await Promise.all([
    prisma.wardenEdrAlert.findMany({ where, orderBy: { createdAt: 'desc' }, take: 200 }),
    prisma.wardenEdrAlert.count({ where }),
    prisma.wardenEdrAlert.count({ where: { ...open, blocked: false } }),
    prisma.wardenEdrAlert.count({ where: open })
  ]);

  // Cross-reference: anything else Warden knows about the people on these machines.
  const mailboxes = [...new Set(rows.map((r) => r.mailbox).filter(Boolean))] as string[];
  const since7 = new Date(Date.now() - 7 * 86_400_000);
  const [flags, reports] = await Promise.all([
    prisma.wardenRiskFlag.groupBy({ by: ['mailbox'], where: { mailbox: { in: mailboxes }, ts: { gte: since7 } }, _count: { _all: true } }),
    prisma.wardenReport.groupBy({ by: ['reporter'], where: { reporter: { in: mailboxes }, reportedAt: { gte: since7 } }, _count: { _all: true } })
  ]);
  const flagBy = new Map(flags.map((f) => [f.mailbox, f._count._all]));
  const repBy = new Map(reports.map((r) => [r.reporter, r._count._all]));

  const t = (d: Date) => fmtTs(d);

  // ── remote-access tool inventory ──────────────────────────────────────────
  // Read from the hourly background snapshot (src/lib/remote-tools-sync.ts). Fetching live
  // took 43 seconds a page load.
  const banned = splitList(s.crowdstrike.bannedTools);
  const approved = splitList(s.crowdstrike.approvedTools);
  const snap = tab === 'tools' ? await readToolSnapshot(prisma) : null;
  const tools = { rows: snap?.rows ?? [], error: snap?.error ?? null, at: snap?.at ?? null };
  const verdictOf = (r: ToolRow) => classify(r, banned, approved);
  const toolRows = tools.rows
    .map((r) => ({ ...r, verdict: verdictOf(r) }))
    .sort(
      (a, b) =>
        ['banned', 'unapproved', 'approved'].indexOf(a.verdict) - ['banned', 'unapproved', 'approved'].indexOf(b.verdict) ||
        String(b.lastUsedAt).localeCompare(String(a.lastUsedAt))
    );
  const flagged = toolRows.filter((r) => r.verdict !== 'approved');
  const okRows = toolRows.filter((r) => r.verdict === 'approved');
  const toolTable = (rows: typeof toolRows) => (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b">
          <th className="th w-28"></th>
          <th className="th">Tool</th>
          <th className="th">Last used by</th>
          <th className="th">PC</th>
          <th className="th w-36">Last used</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={`${r.hostname}-${r.appName}-${i}`} className="border-b last:border-0 align-top">
            <td className="td">
              <span className={`pill ${r.verdict === 'banned' ? 'pill-critical' : r.verdict === 'unapproved' ? 'pill-high' : 'pill-ok'}`}>
                {r.verdict === 'banned' ? 'BANNED' : r.verdict === 'unapproved' ? 'not approved' : 'approved'}
              </span>
            </td>
            <td className="td">
              <div>{r.appName}</div>
              <div className="mono text-xs text-text-muted">{[r.version, r.fileName].filter(Boolean).join(' · ')}</div>
            </td>
            <td className="td text-xs">
              {r.lastUser ? (
                isServiceUser(r.lastUser) ? (
                  <span className="text-warning" title={r.lastUser}>runs as a service — always on</span>
                ) : (
                  <span className="mono">{r.lastUser}</span>
                )
              ) : (
                <span className="text-text-muted">installed, never used</span>
              )}
            </td>
            <td className="td">
              <Link href={`/edr?view=all&host=${encodeURIComponent(r.hostname)}`} className="mono text-xs underline">
                {r.hostname}
              </Link>
            </td>
            <td className="td mono text-xs text-text-muted">
              {r.lastUsedAt ? r.lastUsedAt.slice(0, 16).replace('T', ' ') : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <div className="max-w-6xl space-y-4">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-lg font-semibold">
          <Laptop size={18} /> Endpoint detections
        </h1>
        <p className="text-sm text-text-muted">
          From CrowdStrike Falcon, read-only. Warden cannot contain, kill or remediate &mdash; do that
          in Falcon. <strong className="text-text-primary">Detected only means it ran.</strong>
        </p>
      </header>

      <IngestStatus f={fresh} what="Falcon" />

      <div className="flex flex-wrap gap-1.5 border-b pb-2 text-sm">
        {[
          ['action', `Needs action (${hotRows.length})`],
          ['detections', `Detections (${openCount} open)`],
          ['tools', 'Remote-access tools']
        ].map(([k, label]) => (
          <a
            key={k}
            href={`/edr?tab=${k}`}
            className={`rounded border px-3 py-1.5 ${k === tab ? 'bg-bg-elevated font-medium text-text-primary' : 'text-text-muted'}`}
          >
            {label}
          </a>
        ))}
      </div>

      {tab === 'action' && hotRows.length === 0 && (
        <div className="card text-sm text-text-muted">
          No machine has had an unblocked high/critical detection, an indicator match, or an
          OverWatch lead in the last 14 days.
        </div>
      )}

      {tab === 'action' && hotRows.length > 0 && (
        <div className="card space-y-2" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
          <div className="flex items-center gap-2 text-sm font-semibold">
            <ShieldAlert size={16} style={{ color: 'rgb(var(--danger))' }} /> Machines that need a
            decision &mdash; last 14 days
          </div>
          <p className="text-xs text-text-muted">
            Something ran here unblocked at high/critical severity, touched a known indicator, or drew
            an OverWatch lead. Containment is read live from Falcon.
            {containmentError && <> Containment could not be read: {containmentError}</>}
          </p>
          <table className="w-full border-collapse text-sm">
            <tbody>
              {hotRows.map((h) => {
                const c = containment.get(h.hostname!);
                const contained = c?.status === 'contained';
                return (
                  <tr key={h.hostname} className="border-t">
                    <td className="td">
                      <Link href={`/edr?view=all&host=${encodeURIComponent(h.hostname!)}`} className="mono underline">
                        {h.hostname}
                      </Link>
                    </td>
                    <td className="td">
                      <span className={`pill ${contained ? 'pill-ok' : 'pill-critical'}`}>
                        {c ? (contained ? 'contained' : `NOT contained (${c.status})`) : 'unknown'}
                      </span>
                      {c?.lastSeen && <span className="ml-2 text-xs text-text-muted">seen {c.lastSeen.slice(5, 16).replace('T', ' ')}Z</span>}
                    </td>
                    <td className="td text-xs">{h.users.join(', ') || <span className="text-text-muted">no user (SYSTEM)</span>}</td>
                    <td className="td text-xs">
                      {h._count._all} alert{h._count._all === 1 ? '' : 's'}, latest {h._max.createdAt ? t(h._max.createdAt) : ''}
                      {h.ioc && <div><span className="pill pill-critical">indicator {h.ioc}</span></div>}
                    </td>
                    <td className="td text-xs">
                      {/* Read-only hand-off: jump to the host in Falcon, where Network
                          Containment lives. Warden holds only Alerts:Read/Hosts:Read and never
                          contains a host itself. */}
                      {(() => {
                        const link = falconHostLink(s.crowdstrike.cloud, c?.deviceId);
                        return link ? (
                          <a href={link} target="_blank" rel="noreferrer" className="underline" title="Opens the host in the Falcon console, where Network Containment lives. Warden never contains a host itself.">
                            {contained ? 'View in Falcon ↗' : 'Contain in Falcon ↗'}
                          </a>
                        ) : null;
                      })()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'tools' && (
      <div className="card space-y-2">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <div className="text-sm font-semibold">
            Remote-access tools{' '}
            <span className="font-normal text-text-muted">
              — {flagged.length} flagged, {okRows.length} approved
            </span>
          </div>
          <a href="/settings?tab=CrowdStrike" className="text-xs underline">
            edit watch / banned / approved lists
          </a>
        </div>
        <p className="text-xs text-text-muted">
          From Falcon&rsquo;s application inventory. These are legitimate programs, so no detection
          fires when they run &mdash; an attacker&rsquo;s favourite foothold for exactly that reason.
          Banned tools are red whoever runs them; anything installed but not on the approved list
          is amber. Usage times are to the hour. Inventory refreshed hourly in the background
          {tools.at ? <> &mdash; last pulled {tools.at.slice(0, 16).replace('T', ' ')}Z</> : <> &mdash; not pulled yet; the scheduler fetches it within the hour</>}.
          {tools.error && <strong className="text-danger"> Inventory could not be read: {tools.error}</strong>}
        </p>
        {/*
          Grouped by tool. Flat, this was 1,885 rows — MeshCentral alone is on 886 PCs — and a
          table nobody can scroll is a table nobody reads. One line per tool, worst first;
          expand for the PCs.
        */}
        {flagged.length > 0 && (
          <div className="space-y-1">
            {[...new Set(flagged.map((r) => r.tool))]
              .map((tool) => {
                const rs = flagged.filter((r) => r.tool === tool);
                return {
                  tool,
                  rs,
                  banned: rs.some((r) => r.verdict === 'banned'),
                  pcs: new Set(rs.map((r) => r.hostname)).size,
                  svc: new Set(rs.filter((r) => isServiceUser(r.lastUser)).map((r) => r.hostname)).size,
                  users: new Set(rs.filter((r) => r.lastUser && !isServiceUser(r.lastUser)).map((r) => r.lastUser)).size,
                  latest: rs.map((r) => r.lastUsedAt ?? '').sort().pop() ?? ''
                };
              })
              .sort((a, b) => Number(b.banned) - Number(a.banned) || a.pcs - b.pcs)
              .map((g) => (
                <details key={g.tool} className="rounded border px-3 py-2" open={toolParam === g.tool}>
                  <summary className="flex cursor-pointer flex-wrap items-center gap-2 text-sm">
                    <span className={`pill ${g.banned ? 'pill-critical' : 'pill-high'}`}>
                      {g.banned ? 'BANNED' : 'not approved'}
                    </span>
                    <strong>{g.tool}</strong>
                    <span className="text-xs text-text-muted">
                      {g.pcs} PC{g.pcs === 1 ? '' : 's'}
                      {g.svc > 0 && <> · <span className="text-warning">{g.svc} always-on service</span></>}
                      {g.users > 0 && <> · {g.users} named user{g.users === 1 ? '' : 's'}</>}
                      {g.latest && <> · last used {g.latest.slice(0, 10)}</>}
                    </span>
                  </summary>
                  {/*
                    The PC list is only rendered for the tool you asked for. Embedding every
                    tool's list "in case you expand it" made this tab 2.3 MB — MeshCentral alone
                    is on 886 PCs.
                  */}
                  <div className="mt-2">
                    {toolParam === g.tool ? (
                      <>
                        {toolTable(g.rs.slice(0, 500))}
                        {g.rs.length > 500 && (
                          <p className="mt-1 text-xs text-text-muted">
                            Showing the 500 most recently used of {g.rs.length}. The full list is in
                            Falcon → Exposure management → Applications.
                          </p>
                        )}
                      </>
                    ) : (
                      <a
                        href={`/edr?tab=tools&tool=${encodeURIComponent(g.tool)}`}
                        className="text-xs underline"
                      >
                        Show the {g.pcs} PC{g.pcs === 1 ? '' : 's'}
                      </a>
                    )}
                  </div>
                </details>
              ))}
          </div>
        )}
        {flagged.length === 0 && !tools.error && (
          <p className="text-sm text-text-muted">Nothing installed outside the approved list.</p>
        )}
        {okRows.length > 0 && (
          <details className="text-sm" open={toolParam?.startsWith('approved:')}>
            <summary className="cursor-pointer text-xs text-text-muted">
              {okRows.length} approved install{okRows.length === 1 ? '' : 's'}
            </summary>
            {/* Grouped like the flagged list: one approved tool's PCs at a time, never all 1,300+. */}
            <ul className="mt-1 space-y-1">
              {[...new Set(okRows.map((r) => r.tool))].map((tool) => {
                const rs = okRows.filter((r) => r.tool === tool);
                const pcs = new Set(rs.map((r) => r.hostname)).size;
                return (
                  <li key={tool}>
                    <a href={`/edr?tab=tools&tool=${encodeURIComponent('approved:' + tool)}`} className="text-xs underline">
                      {tool} — {pcs} PC{pcs === 1 ? '' : 's'}
                    </a>
                    {toolParam === 'approved:' + tool && (
                      <div className="mt-1">
                        {toolTable(rs.slice(0, 500))}
                        {rs.length > 500 && (
                          <p className="mt-1 text-xs text-text-muted">Showing the 500 most recently used of {rs.length}.</p>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </details>
        )}
      </div>
      )}

      {tab === 'detections' && (<>
      <div className="flex flex-wrap items-center gap-1.5 text-xs">
        {[
          ['open', `Open (${openCount})`],
          ['ran', `Open & ran — not blocked (${ranCount})`],
          ['all', 'Everything']
        ].map(([k, label]) => (
          <a
            key={k}
            href={`/edr?tab=detections&view=${k}${host ? `&host=${encodeURIComponent(host)}` : ''}`}
            className={`rounded border px-2.5 py-1 ${k === view ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}
          >
            {label}
          </a>
        ))}
        {host && (
          <a href={`/edr?tab=detections&view=${view}`} className="rounded border px-2.5 py-1 text-text-muted">
            host: <span className="mono">{host}</span> ✕
          </a>
        )}
      </div>

      <p className="text-xs text-text-muted">
        {total.toLocaleString()} in this view{total > rows.length && <> &mdash; showing the most recent {rows.length}</>}.
        Status changes made in Falcon flow back here on the next pull.
      </p>

      {rows.length === 0 ? (
        <div className="card text-sm text-text-muted">Nothing in this view.</div>
      ) : (
        <div className="space-y-2">
          {rows.map((r) => {
            const hosts = JSON.parse(r.hosts ?? '[]') as string[];
            return (
              <div
                key={r.compositeId}
                className="card space-y-1.5 text-sm"
                style={!r.blocked && r.severity >= 70 ? { borderColor: 'rgb(var(--danger) / 0.5)' } : undefined}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`pill ${SEV_PILL(r.severity)}`}>{r.severityName}</span>
                  <span className={`pill ${r.blocked ? 'pill-ok' : 'pill-critical'}`}>
                    {r.blocked ? 'BLOCKED' : 'DETECTED ONLY — ran'}
                  </span>
                  {r.product === 'overwatch' && <span className="pill pill-high">OverWatch</span>}
                  {r.iocHit && <span className="pill pill-critical">indicator {r.iocHit}</span>}
                  <strong>{r.displayName ?? r.name ?? 'alert'}</strong>
                  <span className="mono text-xs text-text-muted">{t(r.createdAt)} · {r.status}</span>
                </div>
                <div className="text-xs text-text-muted">
                  <Link href={`/edr?view=all&host=${encodeURIComponent(r.hostname ?? '')}`} className="mono underline">
                    {r.hostname ?? '?'}
                  </Link>
                  {r.localIp && <> · {r.localIp}</>}
                  {r.mailbox ? (
                    <>
                      {' '}· <span className="mono">{r.mailbox}</span>
                      {r.userSource === 'host-usual' && (
                        <span className="text-text-muted" title="The alert predates the login history Falcon still holds. Every sign-in Falcon has for this PC is this one person.">
                          {' '}(usual user of this PC — the only person Falcon has seen sign in; not confirmed at the time)
                        </span>
                      )}
                      {r.userSource === 'host-login' && (
                        <span
                          className="text-text-muted"
                          title={`From Falcon login history: ${r.loginUser ?? ''}. The alert itself ran as SYSTEM.`}
                        >
                          {' '}(signed in to this PC{r.loginAt ? ` at ${fmtTs(r.loginAt)}` : ''} — alert ran as SYSTEM)
                        </span>
                      )}
                      {(flagBy.get(r.mailbox) || repBy.get(r.mailbox)) && (
                        <span className="text-warning">
                          {' '}— also in Warden this week:
                          {flagBy.get(r.mailbox) ? ` ${flagBy.get(r.mailbox)} sign-in flag(s)` : ''}
                          {repBy.get(r.mailbox) ? ` ${repBy.get(r.mailbox)} phish report(s)` : ''}
                        </span>
                      )}{' '}
                      · <Link className="underline" href={`/accounts`}>check account</Link>
                    </>
                  ) : (
                    <> · {r.userName ?? 'no user'}</>
                  )}
                  {r.tactic && <> · {r.tactic}{r.techniqueId ? ` (${r.techniqueId})` : ''}</>}
                </div>
                {hosts.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {hosts.map((h) => (
                      <span key={h} className="pill pill-muted mono text-xs">{h.replace(/\./g, '[.]')}</span>
                    ))}
                  </div>
                )}
                {(r.cmdline || r.parentCmd || r.grandCmd) && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-text-muted">Process tree</summary>
                    <pre className="mono mt-1 overflow-x-auto whitespace-pre-wrap rounded bg-bg-elevated p-2">
                      {[
                        r.grandCmd && `grandparent: ${r.grandCmd}`,
                        r.parentCmd && `  parent: ${r.parentCmd}`,
                        r.cmdline && `    process: ${r.cmdline}`
                      ].filter(Boolean).join('\n')}
                    </pre>
                  </details>
                )}
                {r.falconLink && (
                  <a href={r.falconLink} target="_blank" rel="noreferrer" className="text-xs underline">
                    Open in Falcon
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}
      </>)}
    </div>
  );
}
