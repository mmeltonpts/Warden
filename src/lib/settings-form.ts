/**
 * Shared by the Settings page and the first-run setup wizard, so the two can never
 * disagree about which fields exist or how a form post becomes a settings patch.
 */
import { FIELDS } from './settings';

export type Field = (typeof FIELDS)[number];

export function sectionOf(f: unknown): string {
  return (f as { section?: string }).section ?? 'Other';
}

/**
 * Preferred order: what a new district configures first comes first. This is an ORDERING,
 * not the list. The list is derived from FIELDS, because a hardcoded list silently hides
 * settings: adding six threat-feed fields with a new section name once left all six
 * unreachable in the UI while appearing perfectly fine in the code. Any section not named
 * here still appears, appended at the end.
 */
const PREFERRED = [
  'General',
  'Google Workspace',
  'Notifications',
  'Sounds',
  'Verify',
  'Student notices',
  'Reports',
  'Alerts',
  'Sign-in risk',
  'Quarantine',
  'Hunt',
  'OAuth grants',
  'Forwarding watch',
  'Threat feeds',
  'Data retention',
  'KnowBe4',
  'CrowdStrike',
  'Claude',
  'Schedule'
];

/** Every section present in FIELDS, preferred ones first, stragglers appended. */
export const SECTIONS: string[] = (() => {
  const present = [...new Set(FIELDS.map(sectionOf))];
  const ordered = PREFERRED.filter((p) => present.includes(p));
  const extra = present.filter((p) => !PREFERRED.includes(p)).sort();
  return [...ordered, ...extra];
})();

/** Integrations a district may not have. The wizard offers "Skip" on these. */
export const OPTIONAL_SECTIONS = new Set(['Threat feeds', 'KnowBe4', 'CrowdStrike', 'Claude', 'Verify', 'Student notices', 'OAuth grants', 'Forwarding watch']);

export const BLURB: Record<string, string> = {
  General: 'How people reach this console.',
  'Google Workspace':
    'Where GAM lives and which domains it acts on. Nothing else works until these are right.',
  Schedule:
    'How often each job runs. The cadence lives here rather than in a systemd timer so it can be changed during an incident without root.',
  Reports: 'The mailboxes your Phish Alert Button forwards to, and how far back to look.',
  Alerts:
    'Google Alert Center. Gmail’s own "Report phishing" forwards nothing to anybody — it raises an alert here and that is the entire record.',
  Quarantine:
    'Messages your content-compliance rules held before delivery. They never reach a mailbox, so no scope can find them — Warden reads them from the Gmail delivery log instead. Release and deny stay in the Admin console.',
  'Sign-in risk':
    'Each mailbox is scored against its own learned normal, not a fixed rule. A wider window means better baselines and fewer false positives.',
  Verify:
    'After a risky VPN or foreign sign-in, email the person to ask whether it was them. A reply of NO — or the email being deleted or filtered within minutes, the fingerprint of an attacker rule — raises an alarm. Warden never suspends anyone; this keeps a human in the loop.',
  'Student notices':
    'Queue student VPN sign-ins for the right building administrator to review. Never auto-sent, because sign-in data cannot tell a school device from a personal phone and an iPhone’s default relay looks like a VPN.',
  Sounds:
    'An alarm in every open console when a critical alert arrives — for the room with the console on a screen, where email goes unread.',
  Notifications:
    'Who hears about findings. Roles are resolved at send time, so adding somebody to the console adds them to the paging list.',
  'Threat feeds':
    'Public indicator feeds. These are URL-heavy and Gmail cannot match a domain inside a message body, so they are matched locally against payload hosts already extracted from reported mail — never turned into Gmail searches. Kept apart from your own confirmed indicators.',
  Hunt:
    'Retroactive search for indicators learned after the fact. Read-only — it never deletes. A sender indicator is only searched near the date it was first seen, because a compromised account is the real person either side of that window.',
  'OAuth grants':
    'Optional, read-only. Watches the Admin token log for new apps granted access that can read or change mail — the token-takeover persistence a password reset does not revoke and a mailbox sweep cannot see. Default-deny by client ID: allow-list the mail clients your staff use once, and a grant to anything else is flagged.',
  'Forwarding watch':
    'Optional, read-only. A scheduled tenant-wide audit of auto-forwarding, registered forwarding addresses and delegates — the BEC persistence that survives a password reset. The account check finds these on one mailbox on demand; this watches every mailbox, so forwarding set without a risky sign-in is still caught. A destination outside the district is the exfil signal.',
  CrowdStrike:
    'Optional, read-only. Endpoint detections from Falcon — the attacks mail filtering never sees, like a pasted PowerShell installing remote-access software.',
  KnowBe4:
    'Optional. Pulls phish-prone percentage as context, and can push real-world security events back into KSAT.',
  Claude:
    'Optional. Uses the Claude CLI on this host — no API key. Degrades to manual triage when the session expires.'
};

export function dig(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((a, k) => (a as Record<string, unknown>)?.[k], obj);
}

export function plant(obj: Record<string, unknown>, path: string, value: unknown) {
  const parts = path.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    cur[parts[i]] = { ...((cur[parts[i]] as Record<string, unknown>) ?? {}) };
    cur = cur[parts[i]] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1]] = value;
}

export function fieldsIn(section: string): Field[] {
  return FIELDS.filter((f) => sectionOf(f) === section);
}

export function isRequired(f: Field): boolean {
  return 'required' in f && Boolean(f.required);
}

/**
 * Turn a posted section form into a settings PATCH.
 *
 * Only the fields of one section are in the form, so this must patch, never replace — a
 * full-object write would blank every setting in every other section.
 */
export function patchFromForm(section: string, formData: FormData): Record<string, unknown> {
  const next: Record<string, unknown> = {};
  for (const f of fieldsIn(section)) {
    const raw = formData.get(f.key);
    if (f.type === 'boolean') {
      plant(next, f.key, raw === 'on');
      continue;
    }
    if (f.type === 'textarea') {
      if (raw === null) continue;
      // A multi-line string: keep the newlines, normalise CRLF, drop trailing whitespace.
      plant(next, f.key, String(raw).replace(/\r\n/g, '\n').replace(/\s+$/, ''));
      continue;
    }
    if (f.type === 'list') {
      // One entry per line. An emptied box is a deliberate "none", so it is saved as [].
      if (raw === null) continue;
      plant(next, f.key, String(raw).split(/\r?\n/).map((x) => x.trim()).filter(Boolean));
      continue;
    }
    if (raw === null) continue;
    const str = String(raw).trim();
    // A masked secret means "unchanged" — never write the mask back as the value.
    if ('sensitive' in f && f.sensitive && str.includes('••')) continue;
    // Blank numbers keep their value; blank text is allowed so an operator can clear one.
    if (f.type === 'number') {
      if (str === '' || !Number.isFinite(Number(str))) continue;
      plant(next, f.key, Number(str));
      continue;
    }
    // A required field cannot be blanked from the form: an empty staff domain would be
    // handed to GAM by the next scheduled scan.
    if (str === '' && isRequired(f)) continue;
    if (f.type === 'select' && 'options' in f && !(f.options as readonly string[]).includes(str)) continue;
    plant(next, f.key, str);
  }
  return next;
}

/** Required fields in a section that are still blank in the given settings. */
export function missingRequired(section: string, settings: Record<string, unknown>): Field[] {
  return fieldsIn(section).filter((f) => {
    if (!isRequired(f)) return false;
    const v = dig(settings, f.key);
    return v === undefined || v === null || String(v).trim() === '';
  });
}
