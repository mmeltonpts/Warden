-- CreateEnum
CREATE TYPE "WardenReportState" AS ENUM ('NEW', 'TRIAGED', 'CONFIRMED_PHISH', 'KNOWN_GOOD', 'BENIGN', 'DUPLICATE');

-- CreateTable
CREATE TABLE "WardenReport" (
    "id" TEXT NOT NULL,
    "msgId" TEXT NOT NULL,
    "reporter" TEXT NOT NULL,
    "reportedAt" TIMESTAMP(3) NOT NULL,
    "reportedTo" TEXT,
    "originalSender" TEXT,
    "originalSubject" TEXT,
    "payloadHosts" TEXT,
    "state" "WardenReportState" NOT NULL DEFAULT 'NEW',
    "notes" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "incidentId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenReport_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WardenReport_msgId_key" ON "WardenReport"("msgId");
CREATE INDEX "WardenReport_state_reportedAt_idx" ON "WardenReport"("state", "reportedAt");
CREATE INDEX "WardenReport_originalSender_idx" ON "WardenReport"("originalSender");
CREATE INDEX "WardenReport_originalSubject_idx" ON "WardenReport"("originalSubject");

-- AddForeignKey
ALTER TABLE "WardenReport" ADD CONSTRAINT "WardenReport_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "WardenIncident"("id") ON DELETE SET NULL ON UPDATE CASCADE;
