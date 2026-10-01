-- CrowdStrike Falcon alerts, mirrored read-only. See WardenEdrAlert.
CREATE TABLE "WardenEdrAlert" (
    "compositeId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "severity" INTEGER NOT NULL,
    "severityName" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "product" TEXT,
    "name" TEXT,
    "displayName" TEXT,
    "description" TEXT,
    "tactic" TEXT,
    "technique" TEXT,
    "techniqueId" TEXT,
    "hostname" TEXT,
    "deviceId" TEXT,
    "localIp" TEXT,
    "userName" TEXT,
    "mailbox" TEXT,
    "action" TEXT,
    "blocked" BOOLEAN NOT NULL DEFAULT false,
    "filename" TEXT,
    "cmdline" TEXT,
    "parentCmd" TEXT,
    "grandCmd" TEXT,
    "sha256" TEXT,
    "hosts" TEXT,
    "iocHit" TEXT,
    "falconLink" TEXT,
    "notified" BOOLEAN NOT NULL DEFAULT false,
    "syncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenEdrAlert_pkey" PRIMARY KEY ("compositeId")
);
CREATE INDEX "WardenEdrAlert_createdAt_idx" ON "WardenEdrAlert"("createdAt");
CREATE INDEX "WardenEdrAlert_hostname_idx" ON "WardenEdrAlert"("hostname");
CREATE INDEX "WardenEdrAlert_mailbox_idx" ON "WardenEdrAlert"("mailbox");
CREATE INDEX "WardenEdrAlert_status_severity_idx" ON "WardenEdrAlert"("status", "severity");
