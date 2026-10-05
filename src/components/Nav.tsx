'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldAlert, Search, ListChecks, UserSearch, ScrollText, Settings, LogOut, Users, Inbox, GraduationCap, Siren, ShieldBan, Laptop, MailCheck, KeyRound, Forward
} from 'lucide-react';

const ITEMS = [
  { href: '/risk', label: 'Risk', icon: ShieldAlert, min: 'ANALYST' },
  { href: '/reports', label: 'Reports', icon: Inbox, min: 'ANALYST' },
  { href: '/alerts', label: 'Alerts', icon: Siren, min: 'ANALYST' },
  { href: '/edr', label: 'Endpoints', icon: Laptop, min: 'RESPONDER' },
  { href: '/grants', label: 'OAuth grants', icon: KeyRound, min: 'ANALYST' },
  { href: '/forwarding', label: 'Forwarding', icon: Forward, min: 'ANALYST' },
  { href: '/verify', label: 'Verify', icon: MailCheck, min: 'RESPONDER' },
  { href: '/quarantine', label: 'Quarantine', icon: ShieldBan, min: 'ADMIN' },
  { href: '/scope', label: 'Scope', icon: Search, min: 'ANALYST' },
  { href: '/jobs', label: 'Jobs', icon: ListChecks, min: 'ANALYST' },
  { href: '/accounts', label: 'Accounts', icon: UserSearch, min: 'ANALYST' },
  { href: '/audit', label: 'Audit', icon: ScrollText, min: 'ANALYST' },
  { href: '/knowbe4', label: 'KnowBe4', icon: GraduationCap, min: 'ANALYST' },
  { href: '/users', label: 'Users', icon: Users, min: 'ADMIN' },
  { href: '/settings', label: 'Settings', icon: Settings, min: 'ADMIN' }
] as const;

const RANK: Record<string, number> = { ANALYST: 1, RESPONDER: 2, ADMIN: 3 };

export function Nav({
  role,
  displayName,
  counts
}: {
  role: string;
  displayName: string;
  /** Open-item counts per href, so a queue filling up is visible from any page. */
  counts?: Record<string, number>;
}) {
  // Without this every link rendered identically, so after a ten-minute interruption the
  // only way to tell Reports from Alerts — near-identical screens — was the h1.
  const pathname = usePathname();

  return (
    <nav className="flex w-52 shrink-0 flex-col border-r bg-bg-nav">
      <div className="border-b px-4 py-4">
        <div className="text-sm font-semibold tracking-wide">WARDEN</div>
        <div className="text-xs text-text-muted">incident response</div>
      </div>

      <div className="flex-1 space-y-0.5 p-2">
        {ITEMS.filter((i) => RANK[role] >= RANK[i.min]).map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/');
          const n = counts?.[href] ?? 0;
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? 'page' : undefined}
              className={`flex items-center gap-2.5 rounded px-3 py-2 text-sm hover:bg-bg-elevated hover:text-text-primary ${
                active ? 'bg-bg-elevated font-medium text-text-primary' : 'text-text-muted'
              }`}
            >
              <Icon size={16} />
              <span className="flex-1">{label}</span>
              {n > 0 && <span className="pill pill-muted text-xs">{n}</span>}
            </Link>
          );
        })}
      </div>

      <div className="border-t p-3 text-xs">
        <div className="truncate font-medium">{displayName}</div>
        <div className="mb-2 text-text-muted">{role}</div>
        <form action="/api/auth/logout" method="post">
          <button className="flex items-center gap-1.5 text-text-muted hover:text-text-primary">
            <LogOut size={13} /> Sign out
          </button>
        </form>
      </div>
    </nav>
  );
}
