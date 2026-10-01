import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { currentUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings, getSettingsForDisplay, saveSettings, destructiveAllowed } from '@/lib/settings';
import { SECTIONS, BLURB, fieldsIn, patchFromForm } from '@/lib/settings-form';
import { SettingsFields } from '@/components/SettingsFields';
import { falconHealth } from '@/lib/crowdstrike';
import { ShieldOff, Lock } from 'lucide-react';

export const dynamic = 'force-dynamic';

export default async function SettingsPage({
  searchParams
}: {
  searchParams: Promise<{ tab?: string; saved?: string; test?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect('/login');
  if (user.role !== 'ADMIN') {
    return <div className="card text-sm">Settings require the ADMIN role.</div>;
  }

  const { tab, saved, test } = await searchParams;
  const active = tab && SECTIONS.includes(tab) ? tab : SECTIONS[0];

  const s = (await getSettingsForDisplay(prisma)) as unknown as Record<string, unknown>;
  // Run only when asked, and only on this tab. Uses the STORED (decrypted) settings.
  const csHealth =
    active === 'CrowdStrike' && test
      ? await falconHealth((await getSettings(prisma)).crowdstrike)
      : null;
  const row = await prisma.wardenSetting.findUnique({ where: { key: 'settings' } });

  async function save(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const which = String(formData.get('__section') ?? '');

    const next = patchFromForm(which, formData);
    await saveSettings(prisma, next as never, u.email);
    redirect(`/settings?tab=${encodeURIComponent(which)}&saved=1`);
  }

  return (
    <div className="max-w-3xl space-y-5">
      <header>
        <h1 className="text-lg font-semibold">Settings</h1>
        <p className="text-sm text-text-muted">
          Stored in the database, not <code className="mono">.env</code>. Sensitive values are
          encrypted at rest and shown masked &mdash; leaving a mask in place keeps the stored
          value. The <a href="/setup" className="underline">setup wizard</a> walks through every
          section in order with instructions and connection tests.
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5 text-xs">
        {SECTIONS.map((sec) => {
          const n = fieldsIn(sec).length;
          return (
            <a
              key={sec}
              href={`/settings?tab=${encodeURIComponent(sec)}`}
              className={`rounded border px-2.5 py-1 ${
                sec === active ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'
              }`}
            >
              {sec} <span className="text-text-muted">({n})</span>
            </a>
          );
        })}
      </div>

      {saved && (
        <div className="card text-sm" style={{ borderColor: 'rgb(var(--success) / 0.4)' }}>
          Saved. Other tabs were not touched.
        </div>
      )}

      {BLURB[active] && <p className="text-sm text-text-muted">{BLURB[active]}</p>}

      <form action={save} className="space-y-4">
        <input type="hidden" name="__section" value={active} />
        <SettingsFields section={active} values={s} />

        <button className="btn btn-primary">Save {active}</button>
      </form>

      {active === 'CrowdStrike' && (
        <div className="card space-y-2 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <a href="/settings?tab=CrowdStrike&test=1" className="btn text-xs">
              Test connection
            </a>
            <span className="text-xs text-text-muted">
              Gets a token, then makes one real read per scope. Save first &mdash; it tests the
              stored values, not what is typed in the form.
            </span>
          </div>
          {test && csHealth && (
            <ul className="space-y-1">
              {[csHealth.token, ...csHealth.scopes].map((c) => (
                <li key={c.scope} className="flex flex-wrap items-center gap-2">
                  <span className={`pill ${c.ok ? 'pill-ok' : 'pill-critical'}`}>{c.ok ? 'OK' : 'FAIL'}</span>
                  <strong>{c.scope}</strong>
                  <span className="text-xs text-text-muted">{c.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="card flex items-start gap-2 text-sm">
        {destructiveAllowed() ? (
          <>
            <ShieldOff size={16} className="mt-0.5 shrink-0" style={{ color: 'rgb(var(--danger))' }} />
            <div className="text-text-muted">
              <strong className="text-text-primary">Sweeps are ENABLED on this host.</strong> Mail
              deletion is live. This is gated by a root-owned systemd drop-in, not by anything on
              this page &mdash; a stolen session cannot reach it.
            </div>
          </>
        ) : (
          <>
            <Lock size={16} className="mt-0.5 shrink-0" />
            <div className="text-text-muted">
              <strong className="text-text-primary">Sweeps are refused on this host.</strong> Scope
              and verify work; nothing can delete mail. Enabling it needs root and a service
              restart &mdash; deliberately not a setting on this page, because a setting is
              reachable by anything that steals a session.
            </div>
          </>
        )}
      </div>

      {row?.updatedAt && (
        <p className="text-xs text-text-muted">
          Last changed {row.updatedAt.toISOString().slice(0, 16).replace('T', ' ')} by{' '}
          {row.updatedBy ?? 'unknown'}.
        </p>
      )}
    </div>
  );
}
