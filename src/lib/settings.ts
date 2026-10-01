/**
 * Settings live in the database and the Settings UI — see CLAUDE.md.
 *
 * `.env` carries three bootstraps only: DATABASE_URL, SESSION_SECRET, WARDEN_MASTER_KEY.
 * Anything an operator might plausibly want different is a row here with a form field.
 *
 * Sensitive values are encrypted at rest (AES-256-GCM, src/lib/crypto.ts) and are never
 * sent to the browser in plaintext — the Settings page renders them masked.
 *
 * THE ONE EXCEPTION: WARDEN_ALLOW_DESTRUCTIVE is not here and must never be. It gates
 * district-wide mail deletion and lives in a root-owned systemd drop-in, so a stolen
 * session cannot flip it. See destructiveAllowed() at the bottom.
 */
import type { PrismaClient } from '@prisma/client';
import { DEFAULT_PROTECTED_SUBJECTS, type GamSettings } from './gam';
import { encryptFields, decryptFields, maskFields } from './crypto';
import { KB4_DEFAULTS, type Kb4Settings } from './knowbe4';
import { MAIL_DEFAULTS, type MailSettings } from './mailer';
import { DEFAULT_WATCH } from './remote-tools';

export interface WardenSettings extends GamSettings {
  districtIpPrefix: string;
  consoleUrl: string;
  theme: string;
  reports: { addresses: string; lookbackDays: number; autoIncident: boolean };
  schedule: {
    alertsMinutes: number;
    reportsMinutes: number;
    loginScanMinutes: number;
    knowbe4Minutes: number;
    notifyOnNewReports: boolean;
    notifyOnNewAlerts: boolean;
    notifySeverities: string;
    stuckAfterMinutes: number;
    feedsMinutes: number;
    huntMinutes: number;
    quarantineMinutes: number;
    falconMinutes: number;
  };
  feeds: {
    enabled: boolean;
    abuseChAuthKey: string;
    urlhaus: boolean;
    threatfox: boolean;
    openphish: boolean;
    retentionDays: number;
  };
  hunt: {
    senderWindowDays: number;
  };
  quarantine: {
    notify: boolean;
  };
  sound: {
    enabled: boolean;
    alertSeverities: string;
    falcon: boolean;
    falconSeverities: string;
    tone: string;
    volume: number;
    repeatSeconds: number;
    pollSeconds: number;
  };
  crowdstrike: {
    enabled: boolean;
    cloud: string;
    clientId: string;
    clientSecret: string;
    minSeverity: string;
    notify: boolean;
    watchTools: string;
    bannedTools: string;
    approvedTools: string;
  };
  alerts: {
    enabled: boolean;
    types: string;
    excludeTypes: string;
    lookbackDays: number;
    fetchBodies: boolean;
    rdapEnabled: boolean;
    residentialOrgs: string;
    anonymizerOrgs: string;
    benignNetworks: string;
  };
  baselineWindowDays: number;
  scanLookbackHours: number;
  scanStudentSignIns: boolean;
  homeCountries: string;
  riskFlagThreshold: number;
  ai: { enabled: boolean; command: string[]; timeoutSeconds: number };
  knowbe4: Kb4Settings;
  mail: MailSettings;
}

export const DEFAULTS: WardenSettings = {
  gamPath: '/opt/gam7/gam',
  // Blank until the first-run setup wizard fills them in. Nothing scheduled runs while
  // setup is unfinished, so an empty domain is never handed to GAM.
  domains: { staff: '', students: '' },
  maxToTrashPerMailbox: 25,
  // Label put on everything a sweep trashes. Blank disables.
  sweepWarningLabel: '⚠ PHISHING — DO NOT OPEN',
  scanTimeoutSeconds: 1800,
  protectedSubjects: DEFAULT_PROTECTED_SUBJECTS,
  protectInternalSenders: true,
  districtIpPrefix: '',
  consoleUrl: '',
  theme: 'warden',
  reports: {
    // The mailboxes your Phish Alert Button (or staff) forward suspected phish to. Adding
    // phisher.knowbe4.com reconstructs history from staff Sent folders if the PAB was
    // ever pointed only at KnowBe4.
    addresses: '',
    lookbackDays: 7,
    autoIncident: false
  },
  schedule: {
    // A timer fires every couple of minutes and tick.ts runs only what is due. These are
    // the intervals it checks against, in minutes.
    //
    // Alerts are cheap: one API call, no per-mailbox scan, so they can be polled hard.
    alertsMinutes: 5,
    // Reports are expensive: GAM walks every mailbox in the domain regardless of how
    // narrow the query is, so this is minutes-to-tens-of-minutes of work each time.
    reportsMinutes: 30,
    loginScanMinutes: 180,
    knowbe4Minutes: 720,
    notifyOnNewReports: true,
    notifyOnNewAlerts: true,
    // Which alert severities are worth an email. Everything is still stored and visible.
    notifySeverities: 'HIGH',
    // A run that claims to be in progress for longer than this had its process killed.
    stuckAfterMinutes: 90,
    feedsMinutes: 360,
    // The hunt scopes the domain through GAM, so it is expensive. Twice a day is plenty
    // for indicators that are days or weeks old; live detection is the ingests job.
    huntMinutes: 720,
    // The Gmail delivery log lags delivery by minutes, so polling faster than this buys nothing.
    quarantineMinutes: 10,
    falconMinutes: 5
  },
  feeds: {
    // Public threat feeds. These are URL-heavy, and Gmail cannot match a domain inside
    // a message body — so they are matched LOCALLY against payload hosts Warden has already
    // extracted, never turned into Gmail searches.
    enabled: false,
    // abuse.ch requires a free Auth-Key for URLhaus and ThreatFox. Register at auth.abuse.ch.
    abuseChAuthKey: '',
    urlhaus: true,
    threatfox: true,
    openphish: true,
    // Feeds go stale fast; an indicator nobody has seen in months is noise.
    retentionDays: 30
  },
  crowdstrike: {
    // Read-only pull of Falcon alerts. Off until a key exists.
    enabled: false,
    // us-1 | us-2 | eu-1 | us-gov-1 | us-gov-2 — must match the console the key came from.
    cloud: 'us-1',
    clientId: '',
    clientSecret: '',
    // Informational is ~80% of alerts on this tenant. Kept only if it hits an indicator.
    minSeverity: 'Low',
    notify: true,
    // Remote-access tools to inventory. Legitimate software, so no detection fires on them;
    // the control is knowing which are approved and flagging the rest.
    watchTools: DEFAULT_WATCH,
    bannedTools: 'ScreenConnect, ConnectWise',
    // Empty on purpose: approving a remote-access tool is a decision for the district.
    approvedTools: ''
  },
  sound: {
    // An audible alarm in every open console when a critical alert lands. Email can sit
    // unread for an hour; a sound in the room where the console is open cannot.
    enabled: true,
    // Google Alert Center severities that sound. Google uses HIGH / MEDIUM / LOW.
    alertSeverities: 'HIGH',
    falcon: true,
    falconSeverities: 'High, Critical',
    tone: 'alarm',
    volume: 70,
    // Repeat while the alert is still NEW. 0 sounds once.
    repeatSeconds: 0,
    pollSeconds: 30
  },
  quarantine: {
    // Email the notify list when new messages are held. Quarantined mail is already
    // stopped, so this is awareness, not an emergency — but a BEC aimed at accounts
    // payable is worth knowing about the same hour.
    notify: true
  },
  hunt: {
    // A compromised account is hostile for days and is the real person either side of
    // that. Unscoped, a sender indicator matches a colleague's ordinary mail forever.
    senderWindowDays: 5
  },
  alerts: {
    // Gmail's own 'Report phishing' raises an Alert Center alert and forwards nothing.
    // Data Loss Prevention is deliberately absent: it is 95% of alert volume here and
    // belongs to a different workflow than phishing response.
    enabled: true,
    // BLANK ON PURPOSE = store every alert type Google raises.
    //
    // This was an include list, and an include list fails silently: a new alert type — a
    // custom activity rule you add next week — is fetched, skipped, and never seen again.
    // That is the same shape as 504 reports going to a dead tenant. Exclusions are now
    // named explicitly below, so the default is to notice things.
    types: '',
    // Data Loss Prevention is ~95% of alert volume here (6,990 of 7,350 over 180 days) and
    // is a different workflow: LOW-severity content matches on internal shares. Everything
    // else is kept.
    excludeTypes: 'Data Loss Prevention',
    lookbackDays: 7,
    fetchBodies: true,
    rdapEnabled: true,
    // Matched against the RDAP-registered owner, NOT against the address. This is what
    // makes the rule portable: a district in Texas gets Spectrum and Frontier named for
    // them without anybody typing a prefix.
    residentialOrgs:
      'Comcast, Charter, Spectrum, T-Mobile, AT&T, Verizon, Frontier, Cox Communi, CenturyLink, Lumen, Windstream, Mediacom, WideOpenWest, Astound, Sparklight, Metronet, Uniti, Surf Air, Cellco, Sprint, US Cellular',
    // Never auto-suppressed. A VPN or datacentre address is not a pupil at home, and
    // hiding these would hide the one sign-in that matters.
    anonymizerOrgs:
      'Cloudflare, OVH, DigitalOcean, Linode, Vultr, Hetzner, GTHost, GLOBALTELEHOST, DataCamp, Netprotect, M247, Choopa, Interserver, tzulo, Fastly, Akamai, Amazon, Google LLC, Microsoft, Oracle, Leaseweb, Contabo, Zenlayer, PacketHub, Psychz, ColoCrossing',
    // `prefix=Label`, comma-separated. A "Suspicious login" from one of these is filed
    // BENIGN with the network named, because it is a pupil on a home or carrier connection,
    // not an intrusion. Only nationwide US carrier blocks ship as defaults, each verified
    // against ARIN RDAP rather than guessed from the address. Add your own region's ISPs,
    // nearby colleges and neighbouring districts in the setup wizard.
    //
    // DELIBERATELY ABSENT, and they must stay absent:
    //   2a09:bac2: / 2a09:bac3:  Cloudflare WARP  — a VPN. Usually a pupil evading the
    //                            content filter, but it is an anonymiser and hiding it
    //                            would hide the one case that matters.
    //   2607:5300:               OVH Hosting      — a VPS. Nobody does homework from a
    //                            datacentre.
    //   2a04:4e41:               Fastly           — a proxy/CDN edge.
    benignNetworks: [
      '2601:=Comcast residential',
      '2603:=Comcast residential',
      '2607:fb90:=T-Mobile US',
      '2607:fb91:=T-Mobile US',
      '172.59.=T-Mobile US',
      '2600:387:=AT&T Mobility',
      '2600:382:=AT&T Mobility',
      '2600:1008:=Verizon Wireless',
      '174.209.=Verizon Wireless',
      '2001:1960:=Frontier Communications'
    ].join(', ')
  },
  baselineWindowDays: 45,
  scanLookbackHours: 8,
  // Off by default: it is a much larger population and a much noisier queue, and a
  // district should choose to take that on. The events cost nothing either way.
  scanStudentSignIns: false,
  // ISO country codes where sign-ins are ordinary. Anything else is flagged on its own.
  homeCountries: 'US',
  riskFlagThreshold: 50,
  ai: {
    enabled: false,
    command: ['claude', '-p', '{prompt}', '--output-format', 'json'],
    timeoutSeconds: 120
  },
  knowbe4: KB4_DEFAULTS,
  mail: MAIL_DEFAULTS
};

const KEY = 'settings';

/** Field descriptors drive the Settings form, so adding a setting adds a field. */
export const FIELDS = [
  { section: 'General', key: 'consoleUrl', label: 'Console URL', type: 'text', required: true,
    help: 'The address staff use to reach this console, including the port — for example https://warden.example.org:8443. Used for links in notification emails.' },
  { section: 'General', key: 'theme', label: 'Colour theme', type: 'select', options: ['warden', 'campuslink'],
    help: 'Cosmetic only.' },
  { section: 'Google Workspace', key: 'gamPath', label: 'GAM binary path', type: 'text', sensitive: true,
    help: 'Executed for every scope, sweep and scan. Encrypted at rest.' },
  { section: 'Google Workspace', key: 'domains.staff', label: 'Staff domain', type: 'text', required: true,
    help: 'The primary Google Workspace domain staff mailboxes live in, e.g. example.org. Scopes, sweeps and sign-in scans act on this domain.' },
  { section: 'Google Workspace', key: 'domains.students', label: 'Student domain', type: 'text',
    help: 'If students are on a separate domain or subdomain (e.g. students.example.org). Leave blank if staff and students share one domain.' },
  { section: 'Sign-in risk', key: 'districtIpPrefix', label: 'District egress IP prefix', type: 'text',
    help: 'The start of your public egress address as Google sees it, e.g. "203.0.113." for a /24. Sign-ins from it are somebody inside a building and score lower. Search "what is my IP" from a district PC if unsure. Blank disables the on-network adjustment.' },
  { section: 'Google Workspace', key: 'sweepWarningLabel', label: 'Warning label on swept mail', type: 'text',
    help: "After a sweep, everything it trashed gets this label as a red chip beside the subject, visible in Trash and in search for anyone who goes looking. Gmail does not allow a delivered message to have its subject or body changed, so a label is the strongest marker possible without destroying the evidence. Only mailboxes the sweep actually hit receive the label. Leave blank to disable." },
  { section: 'Google Workspace', key: 'maxToTrashPerMailbox', label: 'Max messages to trash per mailbox', type: 'number',
    help: 'GAM silently under-deletes without this.' },
  { section: 'Google Workspace', key: 'scanTimeoutSeconds', label: 'Job timeout (seconds)', type: 'number',
    help: 'A full-domain scan across 1,360 mailboxes takes 8-15 minutes.' },
  { section: 'Sign-in risk', key: 'baselineWindowDays', label: 'Baseline learning window (days)', type: 'number',
    help: 'How much sign-in history each mailbox is scored against. Used by BOTH the scheduled scan and the backfill script — they previously disagreed, so history was built against one window and scored against another. Wider means better baselines and fewer false positives; a network seen once is never treated as normal.' },
  { section: 'Sign-in risk', key: 'homeCountries', label: 'Home countries (ISO codes, comma-separated)', type: 'text',
    help: 'A sign-in located outside these countries is flagged on its own and is never auto-filed as benign, whatever network it came from. Default US. Add CA or MX if staff routinely cross the border. A VPN exit abroad still flags — the reason text says so, but a person should still confirm it.' },
  { section: 'Sign-in risk', key: 'scanStudentSignIns', label: 'Score student sign-ins too', type: 'boolean',
    help: 'Off by default. The GAM login report is tenant-wide, so student events are already being fetched and discarded — turning this on costs no extra API calls, it only decides what is kept. Expect a much larger and noisier queue: teenagers use VPNs constantly. The Risk page has Staff and Students tabs and a one-click bulk dismiss for the student side, so the noise can be cleared in a pass rather than scrolled past daily. Students get phished too, and a student account sending internal mail is trusted by staff precisely because it is internal.' },
  { section: 'Sign-in risk', key: 'scanLookbackHours', label: 'Scan lookback (hours)', type: 'number',
    help: 'Overlaps the 6-hourly cadence on purpose.' },
  { section: 'Sign-in risk', key: 'riskFlagThreshold', label: 'Risk flag threshold', type: 'number',
    help: 'A sign-in is flagged at or above this score. 50 is the default and what the scoring was tuned against: Google calling a sign-in suspicious is 40 on its own, a network this person has never used is 20, and a relayable MFA challenge passed from an unfamiliar network — what both confirmed takeovers looked like — is 35. Lower it and ordinary travel starts flagging; raise it above 75 and a single strong signal can no longer raise a flag by itself.' },
  { section: 'Google Workspace', key: 'protectInternalSenders', label: 'Never sweep internal senders', type: 'boolean',
    help: 'Protects responders. Turning this off risks deleting your own warnings.' },
  { section: 'Google Workspace', key: 'protectedSubjects', label: 'Never sweep messages with these subjects', type: 'list',
    help: 'One per line. Excluded from every sweep — these are the warnings your staff and IT send about an attack, and they are the record of who caught it. Add the subject prefix your own phish-report button uses.' },
  { section: 'Claude', key: 'ai.enabled', label: 'Claude triage enabled', type: 'boolean',
    help: 'Optional. Degrades to manual when the CLI session expires.' },
  { section: 'Claude', key: 'ai.timeoutSeconds', label: 'Claude timeout (seconds)', type: 'number' },
  { section: 'Claude', key: 'ai.command', label: 'CLI command', type: 'list',
    help: 'One argument per line; {prompt} is replaced with the prompt. The default runs the Claude Code CLI signed in as the warden user (sudo -u warden -H claude, then /login) — no API key is stored here.' },

  { section: 'KnowBe4', key: 'knowbe4.enabled', label: 'KnowBe4 integration', type: 'boolean',
    help: 'Master switch. Off means neither direction runs.' },
  { section: 'KnowBe4', key: 'knowbe4.reportingBaseUrl', label: 'Reporting API base URL', type: 'text',
    help: 'Region-specific: us / eu / ca / uk / de.' },
  { section: 'KnowBe4', key: 'knowbe4.reportingToken', label: 'Reporting API token', type: 'text', sensitive: true,
    help: 'Read-only pull of the KSAT roster and phish-prone percentages, shown on the KnowBe4 page as context for who to call first. It does NOT feed the sign-in risk score — no training metric predicted any of the September compromises, all of which had two-step verification enrolled and enforced. Encrypted at rest.' },
  { section: 'KnowBe4', key: 'knowbe4.userEventsEnabled', label: 'Push user events to KnowBe4', type: 'boolean',
    help: 'Sends confirmed compromises and real phish clicks into KSAT / SecurityCoach.' },
  { section: 'KnowBe4', key: 'knowbe4.userEventsUrl', label: 'User Events API URL', type: 'text',
    help: 'Configurable: the endpoint could not be verified from the JS-rendered docs.' },
  { section: 'KnowBe4', key: 'knowbe4.userEventsToken', label: 'User Events API token', type: 'text', sensitive: true,
    help: 'Account Settings -> Account Integrations -> User Event API -> API Key. Encrypted at rest.' },

  { section: 'Notifications', key: 'mail.enabled', label: 'Email notifications', type: 'boolean',
    help: 'Via Google SMTP relay. No credentials — the relay authorises by source IP.' },
  { section: 'Notifications', key: 'mail.host', label: 'SMTP relay host', type: 'text',
    help: 'smtp-relay.gmail.com for Google Workspace. In the Admin console (Apps → Google Workspace → Gmail → Routing → SMTP relay service) add a rule that allows this host\'s public IP, requires TLS, and does not require SMTP authentication.' },
  { section: 'Notifications', key: 'mail.port', label: 'SMTP relay port', type: 'number', help: '587 with STARTTLS.' },
  { section: 'Notifications', key: 'mail.ehloName', label: 'EHLO hostname', type: 'text',
    help: 'Must be a fully-qualified domain name, e.g. warden.example.org. If this host has a bare hostname with no domain, nodemailer announces EHLO [127.0.0.1] and Google closes the connection with 421-4.7.0 — which looks exactly like an unauthorised IP but is not.' },
  { section: 'Notifications', key: 'mail.from', label: 'Send as', type: 'text',
    help: 'No mailbox needed, but replies bounce unless one exists. Templates say not to reply.' },
  { section: 'Notifications', key: 'mail.notifyAdmins', label: 'Notify all admins', type: 'boolean',
    help: 'Every active account with the ADMIN role. Disabled accounts are excluded automatically.' },
  { section: 'Notifications', key: 'mail.notifyResponders', label: 'Notify all responders', type: 'boolean',
    help: 'Every active RESPONDER — the people who can actually execute a sweep.' },
  { section: 'Notifications', key: 'mail.notifyAnalysts', label: 'Notify all analysts', type: 'boolean',
    help: 'Every active ANALYST. Off by default: analysts are read-only, and paging everyone for every flag is how people learn to ignore the mail.' },
  { section: 'Notifications', key: 'mail.recipients', label: 'Also notify (comma-separated)', type: 'text',
    help: 'Extra addresses added to whichever roles are ticked above — a ticketing queue, a shared inbox, an on-call address. If nothing at all resolves, every active admin is notified rather than nobody: a notification that silently goes nowhere is the failure this tool exists to prevent.' },
  { section: 'Notifications', key: 'mail.throttleMinutes', label: 'Repeat suppression (minutes)', type: 'number',
    help: 'Same notification is not resent inside this window.' },

  { section: 'Reports', key: 'reports.addresses', label: 'Phish report mailboxes', type: 'text',
    help: 'Comma-separated. The mailbox(es) your Phish Alert Button or staff forward suspected phish to, e.g. phishing@example.org. Add phisher.knowbe4.com to reconstruct history from staff Sent folders if the button was ever pointed only at KnowBe4.' },
  { section: 'Reports', key: 'reports.lookbackDays', label: 'Report ingestion lookback (days)', type: 'number',
    help: 'Raise temporarily to backfill, then lower.' },
  { section: 'Reports', key: 'reports.autoIncident', label: 'Auto-open incidents from reports', type: 'boolean',
    help: 'Off by default: a report is a human saying "this looks wrong", not a confirmed finding.' },

  { section: 'Alerts', key: 'alerts.enabled', label: 'Ingest Google Alert Center', type: 'boolean',
    help: 'Gmail’s own "Report phishing" forwards nothing to anybody — it only raises an alert. Without this, those reports are invisible to Warden.' },
  { section: 'Alerts', key: 'alerts.excludeTypes', label: 'Alert types to SKIP', type: 'text',
    help: 'Comma-separated. Everything else is stored. Data Loss Prevention is excluded by default — it is ~95% of alert volume and a different workflow. Prefer excluding what you do not want over listing what you do: an allow-list silently misses any new alert type, including custom activity rules you add later.' },
  { section: 'Alerts', key: 'alerts.types', label: 'Alert types to ingest (leave blank for all)', type: 'text',
    help: 'Comma-separated, matched exactly against Google’s type names. Leave blank for all. "Data Loss Prevention" is excluded by default: it is ~95% of alert volume and belongs to a different workflow.' },
  { section: 'Alerts', key: 'alerts.lookbackDays', label: 'Alert ingestion lookback (days)', type: 'number',
    help: 'Raise temporarily to backfill history, then lower.' },
  { section: 'Alerts', key: 'alerts.fetchBodies', label: 'Fetch the reported message body', type: 'boolean',
    help: 'Google only returns a ~100 character snippet. With this on, Warden looks the message up by rfc822msgid in the reporter’s own mailbox and stores the full body, sender and payload links — the same detail a Phish Alert Button report gets. Costs one GAM call per new alert.' },
  { section: 'Schedule', key: 'schedule.alertsMinutes', label: 'Check Alert Center every (minutes)', type: 'number',
    help: 'Cheap — one API call, no per-mailbox scan — so this can be polled hard. This is the channel Gmail’s own "Report phishing" uses, and a credential harvester does its damage in minutes. 0 disables it.' },
  { section: 'Schedule', key: 'schedule.reportsMinutes', label: 'Check the report mailboxes every (minutes)', type: 'number',
    help: 'Expensive: GAM walks every mailbox in the domain no matter how narrow the query, so each run is minutes of work. Lower it if you can afford the load. 0 disables it.' },
  { section: 'Schedule', key: 'schedule.loginScanMinutes', label: 'Sign-in risk scan every (minutes)', type: 'number',
    help: 'Rebuilds baselines and scores new sign-ins. 0 disables it.' },
  { section: 'Schedule', key: 'schedule.knowbe4Minutes', label: 'KnowBe4 roster sync every (minutes)', type: 'number',
    help: 'The roster changes slowly; twice a day is plenty. 0 disables it.' },
  { section: 'Schedule', key: 'schedule.notifyOnNewReports', label: 'Email on new phish reports', type: 'boolean',
    help: 'Sends a digest grouped by campaign whenever an ingest finds reports nobody has seen.' },
  { section: 'Schedule', key: 'schedule.notifyOnNewAlerts', label: 'Email on new alerts', type: 'boolean',
    help: 'Sign-ins auto-filed as residential are never emailed; only what is left for a human.' },
  { section: 'Schedule', key: 'schedule.notifySeverities', label: 'Email only these alert severities', type: 'text',
    help: 'Comma-separated, e.g. "HIGH" or "HIGH, MEDIUM". Blank means every severity. Everything is stored and visible in the console regardless — this only controls the mail.' },
  { section: 'Schedule', key: 'schedule.stuckAfterMinutes', label: 'Assume a run is stuck after (minutes)', type: 'number',
    help: 'A job holds a lock while it runs so two scans cannot overlap. If a process is killed the lock would otherwise persist forever and that job would silently stop — after this long the lock is broken.' },

  { section: 'Threat feeds', key: 'feeds.enabled', label: 'Pull public threat feeds', type: 'boolean',
    help: 'URLhaus, ThreatFox and OpenPhish. Stored apart from your own confirmed indicators so tens of thousands of unverified rows do not bury them. Matched locally against payload hosts already extracted from reports — never turned into Gmail searches, because Gmail cannot match a domain inside a URL.' },
  { section: 'Threat feeds', key: 'feeds.abuseChAuthKey', label: 'abuse.ch Auth-Key', type: 'text', sensitive: true,
    help: 'Free, from auth.abuse.ch. Required for URLhaus and ThreatFox. Encrypted at rest.' },
  { section: 'Threat feeds', key: 'feeds.urlhaus', label: 'URLhaus (malware URLs)', type: 'boolean' },
  { section: 'Threat feeds', key: 'feeds.threatfox', label: 'ThreatFox (IOCs)', type: 'boolean' },
  { section: 'Threat feeds', key: 'feeds.openphish', label: 'OpenPhish (phishing URLs)', type: 'boolean',
    help: 'Community feed, no key needed.' },
  { section: 'Threat feeds', key: 'feeds.retentionDays', label: 'Discard feed entries older than (days)', type: 'number',
    help: 'Feeds go stale quickly. An indicator nobody has seen in months is noise, not intelligence.' },
  { section: 'CrowdStrike', key: 'crowdstrike.enabled', label: 'Pull Falcon detections', type: 'boolean',
    help: 'Read-only. Alerts and hosts only — Warden never takes action in Falcon.' },
  { section: 'CrowdStrike', key: 'crowdstrike.cloud', label: 'Falcon cloud or API base URL', type: 'text',
    help: 'Paste the Base URL shown on the Falcon API-client page (for example https://api.crowdstrike.com, or https://api.laggar.gcw.crowdstrike.com for GovCloud), or a cloud name: us-1, us-2, eu-1, us-gov-1, us-gov-2. A key only works against its own cloud — GovCloud keys are rejected by the commercial API with HTTP 400. Only CrowdStrike API hosts are accepted.' },
  { section: 'CrowdStrike', key: 'crowdstrike.clientId', label: 'API client ID', type: 'text',
    help: 'Falcon console → Support and resources → API clients and keys → Add new API client. Grant Alerts: Read and Hosts: Read (Assets: Read adds the remote-tool inventory). Do NOT grant Real Time Response: it runs commands on every endpoint, and anything that stole a Warden session would inherit it.' },
  { section: 'CrowdStrike', key: 'crowdstrike.clientSecret', label: 'API client secret', type: 'text', sensitive: true,
    help: 'Shown once by Falcon when the client is created. Encrypted at rest.' },
  { section: 'CrowdStrike', key: 'crowdstrike.watchTools', label: 'Remote-access tools to inventory', type: 'text',
    help: 'Comma-separated name fragments matched against Falcon’s application inventory. Shown on the Endpoints page with who last used each one, on which PC.' },
  { section: 'CrowdStrike', key: 'crowdstrike.bannedTools', label: 'Banned remote-access tools', type: 'text',
    help: 'Always flagged red, whoever runs them — the approved list cannot override a ban. Attackers favour remote-access tools precisely because they are legitimate software: no detection fires for "ScreenConnect ran".' },
  { section: 'CrowdStrike', key: 'crowdstrike.approvedTools', label: 'Approved remote-access tools', type: 'text',
    help: 'Comma-separated. "Splashtop" approves it for anyone; "PuTTY@jane.tech" only for that person; "Parsec@LAB-PC-01" only on that PC. Anything installed but not listed is flagged.' },
  { section: 'CrowdStrike', key: 'crowdstrike.minSeverity', label: 'Lowest severity to keep', type: 'text',
    help: 'Informational, Low, Medium, High or Critical. Informational is typically most of a tenant\'s alerts. Anything matching a Warden indicator, and every OverWatch lead, is kept regardless.' },
  { section: 'CrowdStrike', key: 'crowdstrike.notify', label: 'Email on high/critical, OverWatch, or indicator match', type: 'boolean',
    help: 'Goes to the notify list, and says plainly whether Falcon BLOCKED it or only DETECTED it. Detected means it ran.' },
  { section: 'Schedule', key: 'schedule.falconMinutes', label: 'Pull CrowdStrike detections every (minutes)', type: 'number',
    help: '0 disables.' },
  { section: 'Sounds', key: 'sound.enabled', label: 'Sound an alarm in the console for critical alerts', type: 'boolean',
    help: 'Every open console tab plays a sound and shows a banner when a qualifying alert arrives. Each person can still mute their own browser with the speaker button at the bottom right. Browsers only allow sound after you have clicked somewhere on the page once — the banner says so if it is blocked.' },
  { section: 'Sounds', key: 'sound.alertSeverities', label: 'Google Alert Center severities that sound', type: 'text',
    help: 'Comma-separated: HIGH, MEDIUM, LOW. Default HIGH — Google rates confirmed phishing, suspicious sign-ins to admin accounts and government-backed attacks as HIGH. Adding MEDIUM sounds far more often.' },
  { section: 'Sounds', key: 'sound.falcon', label: 'Also sound for CrowdStrike detections', type: 'boolean',
    help: 'Only when the CrowdStrike integration is on.' },
  { section: 'Sounds', key: 'sound.falconSeverities', label: 'CrowdStrike severities that sound', type: 'text',
    help: 'Comma-separated: Informational, Low, Medium, High, Critical.' },
  { section: 'Sounds', key: 'sound.tone', label: 'Sound', type: 'select', options: ['alarm', 'chime', 'beep'],
    help: 'alarm: two-tone siren, hard to miss. chime: three notes, for a quiet office. beep: three short beeps. Use Test sound to hear it.' },
  { section: 'Sounds', key: 'sound.volume', label: 'Volume (0-100)', type: 'number' },
  { section: 'Sounds', key: 'sound.repeatSeconds', label: 'Repeat every (seconds) until someone triages it', type: 'number',
    help: 'Keeps sounding while the alert is still NEW. 0 sounds once per alert. Something like 120 suits a console left open on a wall screen.' },
  { section: 'Sounds', key: 'sound.pollSeconds', label: 'Check for new alerts every (seconds)', type: 'number',
    help: 'How often each open console asks the server. New alerts are only as fresh as the ingest schedule (Schedule tab), so going below 15 buys nothing.' },
  { section: 'Quarantine', key: 'quarantine.notify', label: 'Email when messages are held in quarantine', type: 'boolean',
    help: 'A digest to the notify list for new holds, at most one per ten minutes. Held mail never reached anyone, so this is awareness rather than an alarm — but a superintendent-impersonation ACH request aimed at accounts payable is worth knowing about the same hour, because the attacker will usually try again by phone.' },
  { section: 'Hunt', key: 'hunt.senderWindowDays', label: 'Search sender indicators within (days) of first sighting', type: 'number',
    help: 'A compromised account is hostile for a few days and is the real person either side of that. Searching a sender indicator with no date window matched a partner district athletic director\'s genuine cross-country and weather-protocol mail — 1,981 findings, almost all of them a colleague doing their job. This is the same trap as sweeping on from: alone, which is refused outright.' },

  { section: 'Schedule', key: 'schedule.feedsMinutes', label: 'Refresh threat feeds every (minutes)', type: 'number',
    help: '0 disables.' },
  { section: 'Schedule', key: 'schedule.quarantineMinutes', label: 'Read admin quarantine every (minutes)', type: 'number',
    help: 'Reads the Gmail delivery log for messages your content-compliance rules quarantined. Quarantined mail never reaches a mailbox, so no scope can see it — this is the only way Warden knows it exists. Google writes the log a few minutes behind delivery. 0 disables.' },
  { section: 'Schedule', key: 'schedule.huntMinutes', label: 'Hunt indicators across the domain every (minutes)', type: 'number',
    help: 'Scopes every curated sender and lure string through GAM, so it walks all mailboxes and is expensive. Twice a day is usually right — live detection is the ingests job, this is for indicators learned after the fact. 0 disables.' },

  { section: 'Alerts', key: 'alerts.rdapEnabled', label: 'Look up who owns each sign-in IP', type: 'boolean',
    help: 'Queries RDAP (the registries’ JSON API — no key needed) and caches the result, so an alert reads "Comcast Cable Communications" instead of an opaque IPv6 address. One outbound lookup per new network, then cached.' },
  { section: 'Alerts', key: 'alerts.residentialOrgs', label: 'Residential / carrier network owners', type: 'text',
    help: 'Comma-separated, matched against the REGISTERED OWNER rather than the address. A suspicious login from one of these is a pupil at home and is filed BENIGN. Because it matches on owner, your own ISPs get identified without you listing a single prefix.' },
  { section: 'Alerts', key: 'alerts.anonymizerOrgs', label: 'VPN / hosting network owners', type: 'text',
    help: 'Never auto-suppressed, whatever else matches. A datacentre or VPN address is not somebody at home — Cloudflare WARP alone is a large share of student sign-ins. Anonymiser wins over residential on a tie.' },
  { section: 'Alerts', key: 'alerts.benignNetworks', label: 'Known-benign login networks (by prefix)', type: 'text',
    help: 'Comma-separated "prefix=Label", e.g. "203.0.113.=Neighbouring district". A Suspicious login from one of these is filed BENIGN with the network named. Add your region\'s home ISPs and nearby colleges (dual enrolment). Residential and mobile carriers only — do NOT add VPN, proxy or hosting ranges (Cloudflare WARP, OVH, Fastly), or you will hide the logins that actually matter.' }
] as const;

/**
 * Read settings, filling anything absent from storage with its default.
 *
 * This MUST deep-merge, for the same reason `saveSettings` does. A shallow
 * `{ ...DEFAULTS, ...stored }` lets the stored `knowbe4` object replace the whole default
 * `knowbe4` block, so any nested key the operator has never set through the form —
 * `knowbe4.eventTypes`, `ai.command` — silently becomes `undefined` at runtime.
 *
 * It is also self-perpetuating, which is what made it hard to see: the lossy read feeds
 * `saveSettings`, which deep-merges the patch onto the already-lossy object and writes it
 * back still missing those keys. Every save re-entrenches the loss. Observed 2026-09-23,
 * when `Object.values(s.eventTypes)` threw in `kb4Health` against a settings row that had
 * been saved several times.
 *
 * Any key added to DEFAULTS after a settings row exists depends on this merge.
 */
export async function getSettings(prisma: PrismaClient): Promise<WardenSettings> {
  const row = await prisma.wardenSetting.findUnique({ where: { key: KEY } });
  if (!row) return DEFAULTS;
  try {
    const stored = decryptFields(JSON.parse(row.value) as Record<string, unknown>);
    return deepMerge(
      DEFAULTS as unknown as Record<string, unknown>,
      stored
    ) as unknown as WardenSettings;
  } catch {
    return DEFAULTS;
  }
}

/** Settings for the browser: secrets masked, never decrypted over the wire. */
export async function getSettingsForDisplay(prisma: PrismaClient) {
  const s = await getSettings(prisma);
  return maskFields(JSON.parse(JSON.stringify(s))) as unknown as WardenSettings;
}

/**
 * Deep merge for nested settings.
 *
 * The Settings form builds its patch with dotted paths, so changing one KnowBe4 token
 * produces `{ knowbe4: { reportingToken: "..." } }` — an object containing ONLY that
 * field. A shallow `{...current, ...next}` then replaces the entire `knowbe4` block and
 * silently wipes the other token. Same trap for `domains` and `ai`.
 *
 * Arrays are replaced wholesale, not merged: `protectedSubjects` and `ai.command` are
 * meant to be set as a unit, and element-wise merging would produce nonsense.
 */
function deepMerge<T extends Record<string, unknown>>(base: T, patch: Record<string, unknown>): T {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) continue;
    const cur = out[k];
    if (
      v && typeof v === 'object' && !Array.isArray(v) &&
      cur && typeof cur === 'object' && !Array.isArray(cur)
    ) {
      out[k] = deepMerge(cur as Record<string, unknown>, v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out as T;
}

export async function saveSettings(
  prisma: PrismaClient,
  next: Partial<WardenSettings>,
  updatedBy: string
): Promise<WardenSettings> {
  const current = (await getSettings(prisma)) as unknown as Record<string, unknown>;
  const merged = deepMerge(current, next as Record<string, unknown>) as unknown as WardenSettings;
  const stored = encryptFields(merged as unknown as Record<string, unknown>);
  await prisma.wardenSetting.upsert({
    where: { key: KEY },
    create: { key: KEY, value: JSON.stringify(stored), updatedBy },
    update: { value: JSON.stringify(stored), updatedBy }
  });
  /**
   * Record the VALUES, not just which keys moved.
   *
   * This used to be `Object.keys(next).join(', ')`, so turning off
   * `protectInternalSenders` — the switch whose own help text says "turning this off risks
   * deleting your own warnings" — audited as the bare word `protectInternalSenders`. After
   * a bad sweep, "was responder protection on at the time?" was unanswerable: WardenSetting
   * keeps only the latest updatedBy/updatedAt, so there is no value history anywhere else.
   *
   * Secrets are named but never printed. A password in an audit log is a password in a log.
   */
  const changed: string[] = [];
  const sensitiveKeys = new Set<string>(
    FIELDS.filter((f) => 'sensitive' in f && f.sensitive).map((f) => f.key as string)
  );
  const walk = (obj: Record<string, unknown>, prefix = '') => {
    for (const [k, v] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        walk(v as Record<string, unknown>, path);
      } else if (sensitiveKeys.has(path)) {
        changed.push(`${path}=<changed>`);
      } else {
        changed.push(`${path}=${Array.isArray(v) ? v.join('|') : String(v)}`);
      }
    }
  };
  walk(next as unknown as Record<string, unknown>);

  await prisma.wardenAudit.create({
    data: {
      operator: updatedBy,
      action: 'settings_update',
      detail: changed.join(', ').slice(0, 1000)
    }
  });
  return merged;
}

/**
 * NOT a database setting, and never will be. Root-owned systemd drop-in at
 * /etc/systemd/system/warden-web.service.d/10-destructive.conf.
 *
 * A UI toggle for this could be flipped by anyone who steals a session cookie. This
 * requires root on the host and a service restart.
 */
export function destructiveAllowed(): boolean {
  return process.env.WARDEN_ALLOW_DESTRUCTIVE === '1';
}

/**
 * Who gets notified. An explicit recipients list wins; otherwise every active ADMIN,
 * so a new admin starts receiving alerts without anyone remembering to add them here.
 */
/**
 * Resolve who gets a notification.
 *
 * Roles are additive and combine with the typed list — ticking "responders" and also
 * naming a shared mailbox gives you both. Resolving by ROLE rather than by a typed list
 * means adding somebody to the console adds them to the paging list; a hand-maintained
 * list goes stale the first time somebody changes jobs and nobody finds out until an
 * incident.
 *
 * Disabled accounts are excluded: revoking someone's access should stop the mail too.
 *
 * The fallback matters. A notification that resolves to nobody fails SILENTLY, which is
 * the exact failure this tool exists to fix — 504 staff reports went to a decommissioned
 * tenant for six months because nothing ever said "this went nowhere". If the settings
 * would produce an empty list, every active admin is notified instead.
 */
export async function notifyRecipients(prisma: PrismaClient): Promise<string[]> {
  const s = await getSettings(prisma);
  const out = new Set<string>();

  const roles: string[] = [];
  if (s.mail.notifyAdmins) roles.push('ADMIN');
  if (s.mail.notifyResponders) roles.push('RESPONDER');
  if (s.mail.notifyAnalysts) roles.push('ANALYST');

  if (roles.length) {
    const users = await prisma.wardenUser.findMany({
      where: { role: { in: roles as never }, disabled: false },
      select: { email: true }
    });
    for (const u of users) out.add(u.email.trim().toLowerCase());
  }

  for (const extra of (s.mail.recipients ?? '').split(',')) {
    const t = extra.trim().toLowerCase();
    if (t) out.add(t);
  }

  if (!out.size) {
    const admins = await prisma.wardenUser.findMany({
      where: { role: 'ADMIN', disabled: false },
      select: { email: true }
    });
    for (const a of admins) out.add(a.email.trim().toLowerCase());
  }

  return [...out];
}
