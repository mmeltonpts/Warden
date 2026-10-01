-- Store the reported message itself. Without it the triage queue shows a subject line and
-- asks an analyst to judge it, which is not a decision anyone can make honestly.

ALTER TABLE "WardenReport" ADD COLUMN "originalTo" TEXT;
ALTER TABLE "WardenReport" ADD COLUMN "payloadUrls" TEXT;
ALTER TABLE "WardenReport" ADD COLUMN "bodyText" TEXT;
