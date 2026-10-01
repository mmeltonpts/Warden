-- Google Workspace Alert Center ingestion.
--
-- Gmail's own "Report phishing" forwards nothing anywhere; it only raises an alert. This
-- is a reporting channel completely separate from the Phish Alert Button, and 101
-- user-reported phishing alerts existed before Warden could read it.

ALTER TABLE "WardenReport" ADD COLUMN "source" TEXT NOT NULL DEFAULT 'PAB';

CREATE TABLE "WardenAlert" (
    "alertId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "source" TEXT,
    "severity" TEXT,
    "googleState" TEXT,
    "createTime" TIMESTAMP(3) NOT NULL,
    "startTime" TIMESTAMP(3),
    "endTime" TIMESTAMP(3),
    "email" TEXT,
    "fromHeader" TEXT,
    "ip" TEXT,
    "subject" TEXT,
    "recipient" TEXT,
    "rfcMessageId" TEXT,
    "bodySnippet" TEXT,
    "attachmentSha" TEXT,
    "messageCount" INTEGER NOT NULL DEFAULT 0,
    "investigateLink" TEXT,
    "state" "WardenReportState" NOT NULL DEFAULT 'NEW',
    "notes" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenAlert_pkey" PRIMARY KEY ("alertId")
);

CREATE INDEX "WardenAlert_type_createTime_idx" ON "WardenAlert"("type", "createTime");
CREATE INDEX "WardenAlert_state_createTime_idx" ON "WardenAlert"("state", "createTime");
