-- Forwarding & delegate watch: a scheduled tenant-wide audit of auto-forwarding, registered
-- forwarding addresses and delegates — the BEC persistence that survives a password reset.
-- Additive only: one new enum, one new table, reusing the existing "WardenRiskState" enum.

CREATE TYPE "WardenPersistKind" AS ENUM ('forward', 'forwardingaddress', 'delegate');

CREATE TABLE "WardenForwardItem" (
    "id" TEXT NOT NULL,
    "mailbox" TEXT NOT NULL,
    "kind" "WardenPersistKind" NOT NULL,
    "target" TEXT NOT NULL,
    "external" BOOLEAN NOT NULL DEFAULT false,
    "detail" TEXT,
    "reasons" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "state" "WardenRiskState" NOT NULL DEFAULT 'NEW',
    "notes" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    CONSTRAINT "WardenForwardItem_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WardenForwardItem_mailbox_kind_target_key" ON "WardenForwardItem"("mailbox", "kind", "target");
CREATE INDEX "WardenForwardItem_active_external_idx" ON "WardenForwardItem"("active", "external");
CREATE INDEX "WardenForwardItem_state_external_idx" ON "WardenForwardItem"("state", "external");
