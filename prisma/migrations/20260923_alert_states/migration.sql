-- Alerts get their own state vocabulary.
--
-- A "Suspicious login" is never phish or spam, and a reported email is never a
-- "compromise". Sharing WardenReportState across both meant the triage buttons offered
-- verdicts that made no sense for half the rows.
--
-- Also: link a report to the Alert Center alert describing the same event. Gmail's own
-- "Report phishing" and the Phish Alert Button are two channels, and one person using both
-- on one message produced two queue entries for one decision.

CREATE TYPE "WardenAlertState" AS ENUM (
  'NEW', 'TRIAGED', 'INVESTIGATING', 'CONFIRMED_PHISH', 'SPAM',
  'KNOWN_GOOD', 'CONFIRMED_COMPROMISE', 'BENIGN', 'DUPLICATE'
);

-- Every existing value ('NEW', 'BENIGN') is present in the new enum, so the cast is total.
ALTER TABLE "WardenAlert" ALTER COLUMN "state" DROP DEFAULT;
ALTER TABLE "WardenAlert" ALTER COLUMN "state" TYPE "WardenAlertState"
  USING "state"::text::"WardenAlertState";
ALTER TABLE "WardenAlert" ALTER COLUMN "state" SET DEFAULT 'NEW';

ALTER TABLE "WardenReport" ADD COLUMN "alertId" TEXT;
ALTER TABLE "WardenReport" ADD COLUMN "dedupeKey" TEXT;

CREATE INDEX "WardenReport_dedupeKey_idx" ON "WardenReport"("dedupeKey");
CREATE INDEX "WardenReport_alertId_idx" ON "WardenReport"("alertId");
