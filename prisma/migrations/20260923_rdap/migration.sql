-- IP ownership enrichment for sign-in alerts.
--
-- "Suspicious login from 2a09:bac2:7e11:25a5::3c0:59" is unreadable, and the whole judgement
-- (a pupil at home, or somebody hiding) turns on who owns the address. RDAP answers that,
-- needs no API key, and returns the allocation CIDR so one lookup covers a whole network.

CREATE TABLE "WardenNetwork" (
    "netKey" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "name" TEXT,
    "org" TEXT,
    "cc" TEXT,
    "source" TEXT,
    "sampleIp" TEXT,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenNetwork_pkey" PRIMARY KEY ("netKey")
);
CREATE INDEX "WardenNetwork_org_idx" ON "WardenNetwork"("org");

ALTER TABLE "WardenAlert" ADD COLUMN "ipOrg" TEXT;
ALTER TABLE "WardenAlert" ADD COLUMN "ipNet" TEXT;
ALTER TABLE "WardenAlert" ADD COLUMN "ipClass" TEXT;
