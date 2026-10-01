/**
 * Import an incident record into Warden from a JSON file.
 *
 *   sudo -u warden npx tsx scripts/import-history.ts private/my-district-history.json
 *
 * Idempotent: IOCs are keyed on value, incidents on name. Safe to re-run.
 *
 * WHY THIS TAKES A FILE RATHER THAN CARRYING THE DATA
 *
 * This script used to hold one district's incident record inline: 21 real email addresses
 * at 15 other organisations, every one of them described as a compromised account, plus
 * five named staff recorded as account-takeover victims with timestamps and attacker IPs.
 *
 * install.sh copies the whole tree to /opt/warden, so shipping that published a peer
 * district's breach on their behalf, without their consent and on somebody else's
 * timetable. Confirming that a partner's account was compromised is information they gave
 * you during an incident; it is not yours to redistribute.
 *
 * Keep your own record in `private/`, which is gitignored.
 *
 * FILE FORMAT — every field optional except where marked:
 *
 * {
 *   "incidents": [
 *     { "name": "Estate-sale advance-fee scam",   // REQUIRED, and the idempotency key
 *       "campaign": "estate-sale",
 *       "openedAt": "2026-09-08T00:00:00Z",
 *       "closedAt": null,
 *       "notes": "What happened, in a sentence." }
 *   ],
 *   "iocs": [
 *     { "value": "evil.example",                  // REQUIRED, and the idempotency key
 *       "kind": "PAYLOAD_HOST",                   // PAYLOAD_HOST | SENDER | LURE_STRING | IP | KNOWN_GOOD
 *       "campaign": "estate-sale",
 *       "firstSeen": "2026-09-08T00:00:00Z",
 *       "notes": "Why this indicator is here and how it was confirmed.",
 *       "incident": "Estate-sale advance-fee scam" }   // matched to incidents[].name
 *   ],
 *   "confirmed": [
 *     { "mailbox": "someone@example.edu",         // REQUIRED
 *       "ts": "2026-09-08T14:02:00Z",
 *       "score": 95,
 *       "reasons": ["Malicious inbox rule created", "Sign-in from a datacentre ASN"],
 *       "ip": "198.51.100.10",
 *       "geo": "US-IN" }
 *   ]
 * }
 *
 * Read-only against Google. Writes only to Warden's own tables.
 */
import { PrismaClient } from '@prisma/client';
import { readFileSync } from 'node:fs';

const prisma = new PrismaClient();

interface HistoryFile {
  incidents?: Array<{
    name: string;
    campaign?: string | null;
    openedAt?: string | null;
    closedAt?: string | null;
    notes?: string | null;
  }>;
  iocs?: Array<{
    value: string;
    kind?: string;
    campaign?: string | null;
    firstSeen?: string | null;
    notes?: string | null;
    incident?: string | null;
  }>;
  confirmed?: Array<{
    mailbox: string;
    ts?: string | null;
    score?: number;
    reasons?: string[];
    ip?: string | null;
    geo?: string | null;
  }>;
}

const VALID_KINDS = ['PAYLOAD_HOST', 'SENDER', 'LURE_STRING', 'IP', 'KNOWN_GOOD'];

function asDate(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

async function main() {
  const path = process.argv[2];
  if (!path) {
    console.error('usage: npx tsx scripts/import-history.ts <file.json>');
    console.error('       see the comment at the top of this file for the format');
    process.exitCode = 1;
    return;
  }

  let doc: HistoryFile;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8')) as HistoryFile;
  } catch (e) {
    console.error(`could not read ${path}: ${(e as Error).message}`);
    process.exitCode = 1;
    return;
  }

  // ── incidents ──────────────────────────────────────────────────────────────
  const incidentIdByName = new Map<string, string>();
  let newIncidents = 0;
  for (const inc of doc.incidents ?? []) {
    if (!inc.name) {
      console.warn('skipping an incident with no name');
      continue;
    }
    const existing = await prisma.wardenIncident.findFirst({ where: { name: inc.name } });
    if (existing) {
      incidentIdByName.set(inc.name, existing.id);
      continue;
    }
    const created = await prisma.wardenIncident.create({
      data: {
        name: inc.name,
        campaign: inc.campaign ?? null,
        openedAt: asDate(inc.openedAt) ?? new Date(),
        closedAt: asDate(inc.closedAt),
        notes: inc.notes ?? null
      }
    });
    incidentIdByName.set(inc.name, created.id);
    newIncidents++;
  }

  // ── indicators ─────────────────────────────────────────────────────────────
  let newIocs = 0;
  let skippedIocs = 0;
  for (const ioc of doc.iocs ?? []) {
    if (!ioc.value) continue;
    const kind = (ioc.kind ?? 'LURE_STRING').toUpperCase();
    if (!VALID_KINDS.includes(kind)) {
      console.warn(`skipping "${ioc.value}": unknown kind "${ioc.kind}"`);
      skippedIocs++;
      continue;
    }
    const existing = await prisma.wardenIoc.findUnique({ where: { value: ioc.value } });
    if (existing) continue;
    await prisma.wardenIoc.create({
      data: {
        value: ioc.value,
        kind: kind as never,
        campaign: ioc.campaign ?? null,
        firstSeen: asDate(ioc.firstSeen),
        notes: ioc.notes ?? null,
        addedBy: 'import-history',
        incidentId: ioc.incident ? (incidentIdByName.get(ioc.incident) ?? null) : null
      }
    });
    newIocs++;
  }

  // ── confirmed compromises ──────────────────────────────────────────────────
  // Recorded as risk flags already in the CONFIRMED_COMPROMISE state, so the history
  // shows up beside live detections rather than in a separate place nobody opens.
  let newFlags = 0;
  for (const c of doc.confirmed ?? []) {
    if (!c.mailbox) continue;
    const ts = asDate(c.ts) ?? new Date();
    const existing = await prisma.wardenRiskFlag.findFirst({
      where: { mailbox: c.mailbox, ts }
    });
    if (existing) continue;
    await prisma.wardenRiskFlag.create({
      data: {
        mailbox: c.mailbox,
        ts,
        score: c.score ?? 100,
        reasons: JSON.stringify(c.reasons ?? ['Imported from incident history']),
        ip: c.ip ?? null,
        geo: c.geo ?? null,
        suspicious: true,
        state: 'CONFIRMED_COMPROMISE',
        notes: 'Imported from incident history.'
      }
    });
    newFlags++;
  }

  console.log(`incidents : ${newIncidents} created, ${(doc.incidents ?? []).length - newIncidents} already present`);
  console.log(`indicators: ${newIocs} created, ${skippedIocs} skipped`);
  console.log(`compromise: ${newFlags} risk flags created`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
