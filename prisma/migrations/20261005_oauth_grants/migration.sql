-- OAuth-grant monitor: new mail-capable grants to apps not on the allow-list — the
-- token-takeover persistence a password reset does not revoke and a mailbox sweep cannot see.
-- Additive only: one new table, reusing the existing "WardenRiskState" enum.

CREATE TABLE "WardenGrantFlag" (
    "id" TEXT NOT NULL,
    "mailbox" TEXT NOT NULL,
    "ts" TIMESTAMP(3) NOT NULL,
    "appName" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientType" TEXT,
    "scopes" TEXT NOT NULL,
    "ip" TEXT,
    "fanOut" INTEGER NOT NULL DEFAULT 1,
    "reasons" TEXT NOT NULL,
    "state" "WardenRiskState" NOT NULL DEFAULT 'NEW',
    "notes" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenGrantFlag_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WardenGrantFlag_mailbox_clientId_ts_key" ON "WardenGrantFlag"("mailbox", "clientId", "ts");
CREATE INDEX "WardenGrantFlag_state_ts_idx" ON "WardenGrantFlag"("state", "ts");
CREATE INDEX "WardenGrantFlag_mailbox_idx" ON "WardenGrantFlag"("mailbox");
