-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "WardenRole" AS ENUM ('ANALYST', 'RESPONDER', 'ADMIN');

-- CreateEnum
CREATE TYPE "WardenJobKind" AS ENUM ('SCOPE', 'SWEEP', 'VERIFY', 'ACCOUNT_CHECK', 'RULE_DRYRUN');

-- CreateEnum
CREATE TYPE "WardenJobStatus" AS ENUM ('QUEUED', 'RUNNING', 'DONE', 'ERROR', 'REFUSED');

-- CreateEnum
CREATE TYPE "WardenIocKind" AS ENUM ('PAYLOAD_HOST', 'SENDER', 'LURE_STRING', 'IP');

-- CreateEnum
CREATE TYPE "WardenRiskState" AS ENUM ('NEW', 'INVESTIGATING', 'CONFIRMED_COMPROMISE', 'BENIGN', 'SUPPRESSED');

-- CreateTable
CREATE TABLE "WardenUser" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "WardenRole" NOT NULL DEFAULT 'ANALYST',
    "disabled" BOOLEAN NOT NULL DEFAULT false,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WardenUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WardenSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenJob" (
    "id" TEXT NOT NULL,
    "kind" "WardenJobKind" NOT NULL,
    "status" "WardenJobStatus" NOT NULL DEFAULT 'QUEUED',
    "operatorId" TEXT NOT NULL,
    "domainKey" TEXT NOT NULL DEFAULT 'staff',
    "query" TEXT,
    "argsJson" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "exitCode" INTEGER,
    "summary" TEXT,
    "logPath" TEXT,
    "parentId" TEXT,
    "incidentId" TEXT,

    CONSTRAINT "WardenJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenFinding" (
    "id" TEXT NOT NULL,
    "jobId" TEXT NOT NULL,
    "mailbox" TEXT,
    "msgId" TEXT,
    "sender" TEXT,
    "subject" TEXT,
    "dateHdr" TEXT,
    "labels" TEXT,

    CONSTRAINT "WardenFinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenIncident" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "campaign" TEXT,
    "openedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closedAt" TIMESTAMP(3),
    "notes" TEXT,

    CONSTRAINT "WardenIncident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenIoc" (
    "id" TEXT NOT NULL,
    "kind" "WardenIocKind" NOT NULL,
    "value" TEXT NOT NULL,
    "campaign" TEXT,
    "firstSeen" TIMESTAMP(3),
    "notes" TEXT,
    "addedBy" TEXT,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "incidentId" TEXT,

    CONSTRAINT "WardenIoc_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenAudit" (
    "id" TEXT NOT NULL,
    "ts" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "operator" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "target" TEXT,
    "query" TEXT,
    "previewCount" INTEGER,
    "resultCount" INTEGER,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "detail" TEXT,

    CONSTRAINT "WardenAudit_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenSetting" (
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "updatedBy" TEXT,

    CONSTRAINT "WardenSetting_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "WardenLoginEvent" (
    "id" TEXT NOT NULL,
    "mailbox" TEXT NOT NULL,
    "ts" TIMESTAMP(3) NOT NULL,
    "eventName" TEXT NOT NULL,
    "ip" TEXT,
    "ipPrefix" TEXT,
    "asn" TEXT,
    "geo" TEXT,
    "challenge" TEXT,
    "suspicious" BOOLEAN NOT NULL DEFAULT false,
    "sensitive" TEXT,
    "userAgent" TEXT,
    "importedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WardenLoginEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenBaseline" (
    "mailbox" TEXT NOT NULL,
    "knownPrefixes" TEXT NOT NULL,
    "knownAsns" TEXT NOT NULL,
    "knownGeos" TEXT NOT NULL,
    "knownChallenges" TEXT NOT NULL,
    "usesPasskey" BOOLEAN NOT NULL DEFAULT false,
    "typicalHours" TEXT NOT NULL,
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "firstSeen" TIMESTAMP(3),
    "lastSeen" TIMESTAMP(3),
    "rebuiltAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "mature" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "WardenBaseline_pkey" PRIMARY KEY ("mailbox")
);

-- CreateTable
CREATE TABLE "WardenRiskFlag" (
    "id" TEXT NOT NULL,
    "mailbox" TEXT NOT NULL,
    "ts" TIMESTAMP(3) NOT NULL,
    "score" INTEGER NOT NULL,
    "reasons" TEXT NOT NULL,
    "ip" TEXT,
    "asn" TEXT,
    "geo" TEXT,
    "challenge" TEXT,
    "suspicious" BOOLEAN NOT NULL DEFAULT false,
    "state" "WardenRiskState" NOT NULL DEFAULT 'NEW',
    "notes" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WardenRiskFlag_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WardenScanRun" (
    "id" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "windowStart" TIMESTAMP(3) NOT NULL,
    "windowEnd" TIMESTAMP(3) NOT NULL,
    "eventsSeen" INTEGER NOT NULL DEFAULT 0,
    "eventsNew" INTEGER NOT NULL DEFAULT 0,
    "flagsRaised" INTEGER NOT NULL DEFAULT 0,
    "baselines" INTEGER NOT NULL DEFAULT 0,
    "ok" BOOLEAN NOT NULL DEFAULT false,
    "error" TEXT,

    CONSTRAINT "WardenScanRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WardenUser_email_key" ON "WardenUser"("email");

-- CreateIndex
CREATE INDEX "WardenSession_userId_idx" ON "WardenSession"("userId");

-- CreateIndex
CREATE INDEX "WardenJob_status_idx" ON "WardenJob"("status");

-- CreateIndex
CREATE INDEX "WardenJob_incidentId_idx" ON "WardenJob"("incidentId");

-- CreateIndex
CREATE INDEX "WardenFinding_jobId_idx" ON "WardenFinding"("jobId");

-- CreateIndex
CREATE INDEX "WardenFinding_sender_idx" ON "WardenFinding"("sender");

-- CreateIndex
CREATE UNIQUE INDEX "WardenIoc_value_key" ON "WardenIoc"("value");

-- CreateIndex
CREATE INDEX "WardenIoc_kind_idx" ON "WardenIoc"("kind");

-- CreateIndex
CREATE INDEX "WardenAudit_ts_idx" ON "WardenAudit"("ts");

-- CreateIndex
CREATE INDEX "WardenLoginEvent_mailbox_ts_idx" ON "WardenLoginEvent"("mailbox", "ts");

-- CreateIndex
CREATE INDEX "WardenLoginEvent_ts_idx" ON "WardenLoginEvent"("ts");

-- CreateIndex
CREATE UNIQUE INDEX "WardenLoginEvent_mailbox_ts_eventName_ip_key" ON "WardenLoginEvent"("mailbox", "ts", "eventName", "ip");

-- CreateIndex
CREATE INDEX "WardenRiskFlag_state_score_idx" ON "WardenRiskFlag"("state", "score");

-- CreateIndex
CREATE INDEX "WardenRiskFlag_mailbox_idx" ON "WardenRiskFlag"("mailbox");

-- CreateIndex
CREATE UNIQUE INDEX "WardenRiskFlag_mailbox_ts_key" ON "WardenRiskFlag"("mailbox", "ts");

-- CreateIndex
CREATE INDEX "WardenScanRun_startedAt_idx" ON "WardenScanRun"("startedAt");

-- AddForeignKey
ALTER TABLE "WardenSession" ADD CONSTRAINT "WardenSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "WardenUser"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WardenJob" ADD CONSTRAINT "WardenJob_operatorId_fkey" FOREIGN KEY ("operatorId") REFERENCES "WardenUser"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WardenJob" ADD CONSTRAINT "WardenJob_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "WardenJob"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WardenJob" ADD CONSTRAINT "WardenJob_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "WardenIncident"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WardenFinding" ADD CONSTRAINT "WardenFinding_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "WardenJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WardenIoc" ADD CONSTRAINT "WardenIoc_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "WardenIncident"("id") ON DELETE SET NULL ON UPDATE CASCADE;

