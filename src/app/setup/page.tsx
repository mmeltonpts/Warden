import { redirect } from 'next/navigation';
import { headers } from 'next/headers';
import { currentUser, createSession, hashPassword } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { getSettings, getSettingsForDisplay, saveSettings, destructiveAllowed } from '@/lib/settings';
import { SECTIONS, BLURB, OPTIONAL_SECTIONS, patchFromForm, missingRequired } from '@/lib/settings-form';
import { SettingsFields } from '@/components/SettingsFields';
import { PendingButton } from '@/components/PendingButton';
import {
  isSetupComplete, hasAnyUser, consumeSetupToken, setupProgress, markStep, completeSetup
} from '@/lib/setup';
import { gamChecks, mailCheck, falconChecks, kb4Checks, claudeChecks, type Check } from '@/lib/setup-checks';
import { CheckCircle2, Circle, MinusCircle } from 'lucide-react';

export const dynamic = 'force-dynamic';

const STEPS = ['Welcome', ...SECTIONS, 'Finish'];

/** Steps with a live connection test, and what the test button says. */
const TESTS: Record<string, string> = {
  'Google Workspace': 'Save & test GAM',
  Notifications: 'Save & send a test email',
  KnowBe4: 'Save & test KnowBe4',
  CrowdStrike: 'Save & test Falcon',
  Claude: 'Save & test Claude'
};

const code = (s: string) => <code className="mono rounded bg-bg-elevated px-1 py-0.5 text-xs">{s}</code>;
const pre = (s: string) => (
  <pre className="mono overflow-x-auto rounded border bg-bg-elevated p-2 text-xs leading-relaxed">{s}</pre>
);

/** What to do OUTSIDE Warden for each step, in the order someone new would do it. */
const GUIDE: Record<string, React.ReactNode> = {
  General: (
    <p>
      The address people type to reach this page. The installer printed it at the end; it is
      usually {code('https://<this host>:<port>')}. Notification emails link back here.
    </p>
  ),
  'Google Workspace': (
    <div className="space-y-2">
      <p>
        Warden acts on mail through <strong>GAM7</strong>, which the installer put at{' '}
        {code('/opt/gam7/gam')} and authorised as the {code('warden')} user. If the test below
        fails, re-run the guided GAM setup on the host:
      </p>
      {pre('sudo /opt/warden/deploy/gam-setup.sh')}
      <p>
        It walks through creating the Google Cloud project, signing in as a super admin, and
        authorising the service account for domain-wide delegation. The last test checks the
        delegation against a real mailbox and, if any scope is missing, gives you a link that
        pre-fills the Admin console with exactly the scopes to add.
      </p>
      <p>
        The service account can read and trash mail in every mailbox. Its key lives only on this
        host, readable only by the {code('warden')} user. Never copy it to a workstation.
      </p>
    </div>
  ),
  Notifications: (
    <div className="space-y-2">
      <p>Warden sends mail through Google&apos;s SMTP relay, which authorises by source IP — no password is stored.</p>
      <ol className="list-decimal space-y-1 pl-5">
        <li>Admin console → Apps → Google Workspace → Gmail → Routing → <strong>SMTP relay service</strong> → Configure.</li>
        <li>Allowed senders: <em>Only addresses in my domains</em>. Authentication: tick <em>Only accept mail from the specified IP addresses</em> and add this host&apos;s public egress IP. Tick <em>Require TLS encryption</em>.</li>
        <li>Set <strong>Send as</strong> below to an address in your domain (e.g. {code('warden@your-domain')}). It does not need a mailbox, but replies bounce without one.</li>
        <li>Set <strong>EHLO hostname</strong> to this host&apos;s fully-qualified name.</li>
      </ol>
      <p>Changes to the relay take a few minutes to apply. The test sends to your own address.</p>
    </div>
  ),
  Reports: (
    <div className="space-y-2">
      <p>
        Create a mailbox or Google Group that staff forward suspected phish to (e.g.{' '}
        {code('phishing@your-domain')}), and point your Phish Alert Button at it. Warden reads
        it through GAM — no mailbox password needed.
      </p>
      <p>Leave &quot;auto-open incidents&quot; off until you trust the queue: a report is a person saying &quot;this looks wrong&quot;, not a confirmed finding.</p>
    </div>
  ),
  Alerts: (
    <p>
      Nothing to set up in Google: Alert Center access comes with the GAM admin authorisation.
      Gmail&apos;s own &quot;Report phishing&quot; button raises an alert here and forwards nothing to anyone,
      so this is the only place those reports appear.
    </p>
  ),
  'Sign-in risk': (
    <div className="space-y-2">
      <p>
        Find your district&apos;s public egress IP by searching &quot;what is my IP&quot; from a district PC,
        and enter the start of it as the egress prefix (e.g. {code('203.0.113.')}). Sign-ins from
        inside your buildings then score lower.
      </p>
      <p>
        Under Alerts → known-benign networks you can add your region&apos;s home ISPs and nearby
        colleges later; the defaults cover national US carriers only.
      </p>
    </div>
  ),
  Quarantine: (
    <p>
      Only relevant if you use Gmail content-compliance rules that send mail to admin
      quarantine. Warden reads held messages from the Gmail delivery log; release and deny stay
      in the Admin console. This page is visible to admins only.
    </p>
  ),
  Hunt: <p>The defaults are sensible. The hunt only reads mail; it never deletes anything.</p>,
  'Threat feeds': (
    <p>
      Optional. URLhaus and ThreatFox need a free Auth-Key from {code('auth.abuse.ch')}; OpenPhish
      needs nothing. Skip this if you are not sure — it can be turned on any time from Settings.
    </p>
  ),
  KnowBe4: (
    <div className="space-y-2">
      <p>Optional. Both tokens come from the KnowBe4 console:</p>
      <ul className="list-disc space-y-1 pl-5">
        <li><strong>Reporting API</strong>: Account Settings → Account Integrations → API → Reporting API → token. Pick the base URL for your region.</li>
        <li><strong>User Events API</strong>: Account Settings → Account Integrations → User Event API → API key.</li>
      </ul>
    </div>
  ),
  CrowdStrike: (
    <div className="space-y-2">
      <p>Optional. In Falcon: Support and resources → API clients and keys → Add new API client. Grant:</p>
      <ul className="list-disc space-y-1 pl-5">
        <li><strong>Alerts: Read</strong> and <strong>Hosts: Read</strong> — detections and who was signed in.</li>
        <li><strong>Assets: Read</strong> (Falcon Discover) — optional, enables the remote-access tool inventory.</li>
      </ul>
      <p>
        Do <strong>not</strong> grant Real Time Response. Copy the Base URL Falcon shows with the
        key into the cloud field — a GovCloud key does not work against the commercial API.
      </p>
    </div>
  ),
  Claude: (
    <div className="space-y-2">
      <p>
        Optional AI triage of reported messages, using the Claude Code CLI signed in with your
        Claude subscription — no API key is stored. The installer offers to install it; to sign
        in, on the host run:
      </p>
      {pre('sudo -u warden -H claude\n# then type /login and follow the link')}
      <p>When the session expires, triage falls back to manual; nothing else is affected.</p>
    </div>
  ),
  Schedule: (
    <p>
      How often each background job runs. The defaults suit most districts; every interval can
      be changed later, during an incident, without touching the host. 0 turns a job off.
    </p>
  )
};

function nextStep(step: string): string {
  const i = STEPS.indexOf(step);
  return STEPS[Math.min(STEPS.length - 1, i + 1)];
}
const href = (step: string, extra = '') => `/setup?step=${encodeURIComponent(step)}${extra}`;

// Plain helper, not an action, at module scope so the inline actions do not have to
// close over it (an inline action can only capture serialisable values).
async function saveSection(formData: FormData, then: 'next' | 'test') {
  const u = await currentUser();
  if (!u || u.role !== 'ADMIN') redirect('/login');
  const section = String(formData.get('__section') ?? '');
  if (!SECTIONS.includes(section)) redirect(href('Welcome'));
  await saveSettings(prisma, patchFromForm(section, formData) as never, u.email);
  const now = (await getSettings(prisma)) as unknown as Record<string, unknown>;
  if (missingRequired(section, now).length) redirect(href(section, '&error=required'));
  await markStep(prisma, section, 'saved', u.email);
  redirect(then === 'test' ? href(section, '&check=1') : href(nextStep(section)));
}

export default async function SetupPage({
  searchParams
}: {
  searchParams: Promise<{ step?: string; check?: string; error?: string }>;
}) {
  const { step: stepParam, check, error } = await searchParams;

  // ── 1. Claim: no accounts exist yet ─────────────────────────────────────────
  if (!(await hasAnyUser(prisma))) {
    async function claim(formData: FormData) {
      'use server';
      const token = String(formData.get('token') ?? '');
      const email = String(formData.get('email') ?? '').trim().toLowerCase();
      const name = String(formData.get('name') ?? '').trim();
      const pw = String(formData.get('password') ?? '');
      const pw2 = String(formData.get('password2') ?? '');
      if (!email.includes('@')) redirect('/setup?error=email');
      if (pw.length < 12) redirect('/setup?error=short');
      if (pw !== pw2) redirect('/setup?error=match');
      // Re-check inside the action: two people racing the same fresh console must not
      // both end up as admins.
      if (await hasAnyUser(prisma)) redirect('/login');
      if (!(await consumeSetupToken(prisma, token))) redirect('/setup?error=token');
      const u = await prisma.wardenUser.create({
        data: { email, displayName: name || email.split('@')[0], passwordHash: await hashPassword(pw), role: 'ADMIN' }
      });
      await prisma.wardenAudit.create({ data: { operator: email, action: 'user_create', target: email, detail: 'first ADMIN, claimed at /setup' } });
      await createSession(u.id);
      redirect(href('Welcome'));
    }
    const msg: Record<string, string> = {
      token: 'That setup code is wrong or has expired. Print a new one on the host (command below).',
      email: 'Enter a valid email address.',
      short: 'Use a password of at least 12 characters.',
      match: 'The two passwords do not match.'
    };
    return (
      <div className="mx-auto mt-16 w-full max-w-md space-y-4">
        <div className="text-center">
          <div className="text-lg font-semibold tracking-wide">WARDEN</div>
          <div className="text-xs text-text-muted">first-run setup</div>
        </div>
        <form action={claim} className="card space-y-3">
          <p className="text-sm text-text-muted">
            Create the first administrator. You need the one-time setup code the installer
            printed on the host&apos;s terminal — it proves you are the person who installed this
            console, not just the first person on the network to reach it.
          </p>
          {error && msg[error] && (
            <div className="rounded border px-3 py-2 text-sm" style={{ background: 'rgb(var(--danger) / 0.12)', color: 'rgb(var(--danger))' }}>
              {msg[error]}
            </div>
          )}
          {[
            ['token', 'Setup code', 'text', true],
            ['email', 'Your email', 'email', false],
            ['name', 'Your name', 'text', false],
            ['password', 'Password (12+ characters)', 'password', false],
            ['password2', 'Password again', 'password', false]
          ].map(([n, label, type, focus]) => (
            <label key={String(n)} className="block text-sm">
              <span className="mb-1 block text-text-muted">{label}</span>
              <input name={String(n)} type={String(type)} required={n !== 'name'} autoFocus={Boolean(focus)}
                     autoComplete={n === 'token' ? 'off' : undefined}
                     className="w-full rounded border bg-bg-elevated px-3 py-2 text-sm" />
            </label>
          ))}
          <PendingButton className="btn btn-primary w-full justify-center" pending="Creating…">Create administrator</PendingButton>
        </form>
        <div className="card text-xs text-text-muted">
          Lost or expired code? On the host:
          {pre('sudo -u warden -H bash -c "cd /opt/warden && npx tsx scripts/setup-token.ts"')}
        </div>
      </div>
    );
  }

  // ── 2. The wizard: ADMIN only ───────────────────────────────────────────────
  const user = await currentUser();
  if (!user) redirect('/login');
  if (user.role !== 'ADMIN') {
    return <div className="card text-sm">Setup can only be completed by an ADMIN.</div>;
  }

  const step = stepParam && STEPS.includes(stepParam) ? stepParam : 'Welcome';
  const complete = await isSetupComplete(prisma);
  const progress = await setupProgress(prisma);
  const display = (await getSettingsForDisplay(prisma)) as unknown as Record<string, unknown>;

  // Suggest the address this page was actually loaded from.
  if (!display.consoleUrl) {
    const h = await headers();
    const host = h.get('x-forwarded-host') ?? h.get('host');
    const proto = h.get('x-forwarded-proto') ?? 'http';
    if (host) display.consoleUrl = `${proto}://${host}`;
  }

  async function save(formData: FormData) {
    'use server';
    await saveSection(formData, 'next');
  }
  async function saveAndTest(formData: FormData) {
    'use server';
    await saveSection(formData, 'test');
  }

  async function skip(formData: FormData) {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const section = String(formData.get('__section') ?? '');
    if (OPTIONAL_SECTIONS.has(section)) await markStep(prisma, section, 'skipped', u.email);
    redirect(href(nextStep(section)));
  }

  async function finish() {
    'use server';
    const u = await currentUser();
    if (!u || u.role !== 'ADMIN') redirect('/login');
    const now = (await getSettings(prisma)) as unknown as Record<string, unknown>;
    const missing = SECTIONS.flatMap((s) => missingRequired(s, now));
    if (missing.length) redirect(href('Finish', '&error=required'));
    await completeSetup(prisma, u.email);
    redirect('/risk');
  }

  // Run the connection test only when asked for, against what was just saved.
  let checks: Check[] | null = null;
  if (check && TESTS[step]) {
    const staff = String((display.domains as { staff?: string })?.staff ?? '');
    const testBox = user.email.endsWith(`@${staff}`) ? user.email : '';
    checks =
      step === 'Google Workspace' ? await gamChecks(prisma, testBox)
      : step === 'Notifications' ? await mailCheck(prisma, user.email)
      : step === 'CrowdStrike' ? await falconChecks(prisma)
      : step === 'KnowBe4' ? await kb4Checks(prisma)
      : await claudeChecks(prisma);
  }

  const missingAll = SECTIONS.flatMap((s) => missingRequired(s, display).map((f) => `${s}: ${f.label}`));

  return (
    <div className="flex max-w-5xl flex-col gap-6 md:flex-row">
      <nav className="shrink-0 md:w-52">
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Setup</div>
        <ol className="space-y-0.5 text-sm">
          {STEPS.map((s) => {
            const st = progress[s];
            const Icon = st === 'saved' ? CheckCircle2 : st === 'skipped' ? MinusCircle : Circle;
            return (
              <li key={s}>
                <a href={href(s)} className={`flex items-center gap-2 rounded px-2 py-1 ${s === step ? 'bg-bg-elevated text-text-primary' : 'text-text-muted'}`}>
                  <Icon size={14} className="shrink-0" style={st === 'saved' ? { color: 'rgb(var(--success))' } : undefined} />
                  {s}
                  {OPTIONAL_SECTIONS.has(s) && <span className="text-[10px] text-text-muted">optional</span>}
                </a>
              </li>
            );
          })}
        </ol>
      </nav>

      <div className="min-w-0 flex-1 space-y-4">
        {complete && (
          <div className="card text-xs text-text-muted">
            Setup was finished earlier. Anything saved here takes effect immediately — this is the
            same as editing <a href="/settings" className="underline">Settings</a>, with instructions.
          </div>
        )}

        <h1 className="text-lg font-semibold">{step}</h1>

        {step === 'Welcome' && (
          <div className="card space-y-3 text-sm">
            <p>
              This walks through every setting in order, with what to do in Google, KnowBe4 and
              CrowdStrike at each step and a test button where one exists. It takes about twenty
              minutes. Everything can be changed later from Settings.
            </p>
            <p className="font-medium">Have these ready:</p>
            <ul className="list-disc space-y-1 pl-5 text-text-muted">
              <li>A Google Workspace <strong>super admin</strong> account (for GAM and the SMTP relay).</li>
              <li>The address staff forward phish to, or permission to create one.</li>
              <li>Your district&apos;s public egress IP.</li>
              <li>Optional: KnowBe4 API tokens, a CrowdStrike API client, an abuse.ch key, a Claude subscription.</li>
            </ul>
            <p className="text-text-muted">
              <strong className="text-text-primary">Nothing runs until you press Finish.</strong> The
              scheduler skips every job while setup is incomplete, so a half-configured console never
              scans with an empty domain.
            </p>
            <a href={href(nextStep('Welcome'))} className="btn btn-primary inline-flex">Start</a>
          </div>
        )}

        {SECTIONS.includes(step) && (
          <>
            {BLURB[step] && <p className="text-sm text-text-muted">{BLURB[step]}</p>}
            {GUIDE[step] && <div className="card space-y-2 text-sm">{GUIDE[step]}</div>}

            {error === 'required' && (
              <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
                Fill in the required fields before continuing.
              </div>
            )}

            {checks && (
              <div className="card space-y-1.5 text-sm">
                {checks.map((c) => (
                  <div key={c.name} className="flex flex-wrap items-start gap-2">
                    <span className={`pill ${c.ok ? 'pill-ok' : 'pill-critical'}`}>{c.ok ? 'PASS' : 'FAIL'}</span>
                    <strong>{c.name}</strong>
                    <span className="text-xs text-text-muted">{c.detail}</span>
                    {c.link && (
                      <a href={c.link} target="_blank" rel="noreferrer" className="text-xs underline">
                        Authorise the missing scopes in the Admin console
                      </a>
                    )}
                  </div>
                ))}
                {checks.every((c) => c.ok) && (
                  <a href={href(nextStep(step))} className="btn btn-primary mt-2 inline-flex text-xs">Continue</a>
                )}
              </div>
            )}

            <form action={save} className="space-y-4">
              <input type="hidden" name="__section" value={step} />
              <SettingsFields section={step} values={display} />
              <div className="flex flex-wrap gap-2">
                <PendingButton className="btn btn-primary" pending="Saving…">Save &amp; continue</PendingButton>
                {TESTS[step] && (
                  <PendingButton className="btn" formAction={saveAndTest} pending="Testing…">
                    {TESTS[step]}
                  </PendingButton>
                )}
              </div>
            </form>
            {OPTIONAL_SECTIONS.has(step) && (
              <form action={skip}>
                <input type="hidden" name="__section" value={step} />
                <button className="text-xs text-text-muted underline">Skip — we don&apos;t use this</button>
              </form>
            )}
          </>
        )}

        {step === 'Finish' && (
          <div className="space-y-4">
            <div className="card space-y-2 text-sm">
              <p className="font-medium">Sections</p>
              <ul className="space-y-0.5 text-text-muted">
                {SECTIONS.map((s) => (
                  <li key={s}>
                    <a href={href(s)} className="underline">{s}</a>:{' '}
                    {progress[s] === 'saved' ? 'saved' : progress[s] === 'skipped' ? 'skipped' : 'defaults (not reviewed)'}
                  </li>
                ))}
              </ul>
              {missingAll.length > 0 && (
                <p style={{ color: 'rgb(var(--danger))' }}>Still required: {missingAll.join('; ')}</p>
              )}
            </div>

            <div className="card space-y-2 text-sm">
              <p className="font-medium">Before your first incident</p>
              <ol className="list-decimal space-y-1 pl-5 text-text-muted">
                <li>Add your team under <a href="/users" className="underline">Users</a>. ANALYST is read-only, RESPONDER can run sweeps, ADMIN can change settings.</li>
                <li>Run a <a href="/scope" className="underline">Scope</a> job for a subject you know exists and read the preview. Scope never changes mail.</li>
                <li>
                  Sweeps (trashing mail across mailboxes) are{' '}
                  <strong className="text-text-primary">{destructiveAllowed() ? 'ENABLED' : 'refused'}</strong> on this host.
                  That switch is deliberately not in this console — a setting here could be flipped
                  by anyone who stole a session. To enable sweeps, as root on the host:
                  {pre('sudo sed -i "s/WARDEN_ALLOW_DESTRUCTIVE=0/WARDEN_ALLOW_DESTRUCTIVE=1/" \\\n  /etc/systemd/system/warden-web.service.d/10-destructive.conf\nsudo systemctl daemon-reload && sudo systemctl restart warden-web')}
                </li>
              </ol>
            </div>

            {error === 'required' && (
              <div className="card text-sm" style={{ borderColor: 'rgb(var(--danger) / 0.5)' }}>
                Some required settings are still blank — see the list above.
              </div>
            )}
            <form action={finish}>
              <PendingButton className="btn btn-primary" pending="Finishing…">
                {complete ? 'Done' : 'Finish setup and start the scheduler'}
              </PendingButton>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}
