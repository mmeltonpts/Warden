import type { Metadata } from 'next';
import './globals.css';
import { resolveTheme, themeStyle } from '@/core/themes';
import { currentUser } from '@/lib/auth';
import { destructiveAllowed, getSettings } from '@/lib/settings';
import { isSetupComplete } from '@/lib/setup';
import { Nav } from '@/components/Nav';
import { AlertSound } from '@/components/AlertSound';
import { prisma } from '@/lib/db';

export const metadata: Metadata = {
  title: 'Warden',
  description: 'Phishing incident response console'
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = resolveTheme(await getSettings(prisma).then((s) => s.theme).catch(() => undefined));
  const user = await currentUser();
  const setupDone = user ? await isSetupComplete(prisma).catch(() => true) : true;

  // Open-work counts in the nav. Without them, a queue filling up during an incident is
  // invisible from every other page, and the operator only finds out by going to look.
  const counts = user
    ? await (async () => {
        const canRespond = user.role === 'RESPONDER' || user.role === 'ADMIN';
        const [reports, alerts, risk, quarantine, verify, grants, forwarding] = await Promise.all([
          prisma.wardenReport.count({ where: { state: 'NEW' } }),
          prisma.wardenAlert.count({ where: { state: 'NEW' } }),
          prisma.wardenRiskFlag.count({ where: { state: 'NEW' } }),
          user.role === 'ADMIN' ? prisma.wardenQuarantine.count({ where: { reviewedBy: null } }) : Promise.resolve(0),
          canRespond ? prisma.wardenStudentVpnNotice.count({ where: { state: 'QUEUED' } }) : Promise.resolve(0),
          prisma.wardenGrantFlag.count({ where: { state: 'NEW' } }),
          prisma.wardenForwardItem.count({ where: { state: 'NEW', external: true } })
        ]);
        return {
          '/reports': reports, '/alerts': alerts, '/risk': risk, '/grants': grants, '/forwarding': forwarding,
          ...(user.role === 'ADMIN' ? { '/quarantine': quarantine } : {}),
          ...(canRespond ? { '/verify': verify } : {})
        };
      })().catch(() => undefined)
    : undefined;

  return (
    <html lang="en" className="dark">
      <head>
        <style dangerouslySetInnerHTML={{ __html: themeStyle(theme) }} />
      </head>
      <body className="font-sans antialiased">
        {/* A standing reminder of which mode the server is in. When sweeps are live,
            this banner is the only thing on screen that is always red. */}
        {user && destructiveAllowed() && (
          <div
            className="px-4 py-1 text-center text-xs font-semibold"
            style={{ background: 'rgb(var(--danger))', color: '#fff' }}
          >
            SWEEPS ARE ARMED ON THIS HOST — a sweep run here can trash mail across every
            mailbox in the chosen domain. Nothing is being deleted right now.
          </div>
        )}
        {/* Until setup is finished the scheduler runs nothing, which is silent by design —
            so say so on every page rather than let an unconfigured console look idle. */}
        {user && !setupDone && (
          <div className="border-b px-4 py-1.5 text-center text-xs" style={{ background: 'rgb(var(--warning) / 0.15)' }}>
            Setup is not finished — no scheduled jobs run until it is.{' '}
            {user.role === 'ADMIN' ? (
              <a href="/setup" className="font-semibold underline">Continue setup</a>
            ) : (
              <span>An administrator needs to complete it.</span>
            )}
          </div>
        )}
        <div className="flex min-h-screen">
          {user && <Nav role={user.role} displayName={user.displayName} counts={counts} />}
          <main className="flex-1 overflow-x-hidden p-6">{children}</main>
        </div>
        {user && <AlertSound />}
      </body>
    </html>
  );
}
