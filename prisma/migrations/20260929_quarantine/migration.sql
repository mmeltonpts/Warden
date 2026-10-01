-- Admin-quarantine record, read from the Gmail delivery log. See WardenQuarantine.
CREATE TABLE "WardenQuarantine" (
    "id" TEXT NOT NULL,
    "msgId" TEXT NOT NULL,
    "recipient" TEXT NOT NULL,
    "sender" TEXT,
    "subject" TEXT,
    "senderIp" TEXT,
    "attachments" INTEGER NOT NULL DEFAULT 0,
    "linkDomains" TEXT,
    "rules" TEXT NOT NULL,
    "ruleName" TEXT,
    "matched" TEXT,
    "heldAt" TIMESTAMP(3) NOT NULL,
    "iocHit" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "notes" TEXT,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenQuarantine_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WardenQuarantine_msgId_recipient_key" ON "WardenQuarantine"("msgId", "recipient");
CREATE INDEX "WardenQuarantine_heldAt_idx" ON "WardenQuarantine"("heldAt");
CREATE INDEX "WardenQuarantine_ruleName_idx" ON "WardenQuarantine"("ruleName");
