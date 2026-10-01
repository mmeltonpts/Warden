-- Public threat feeds, and a record of what they matched.
--
-- Feeds live apart from the curated IOC table on purpose: tens of thousands of unverified
-- rows would bury the indicators somebody here confirmed by hand.

CREATE TABLE "WardenFeedIoc" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "host" TEXT,
    "malware" TEXT,
    "firstSeen" TIMESTAMP(3),
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenFeedIoc_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WardenFeedIoc_source_value_key" ON "WardenFeedIoc"("source", "value");
CREATE INDEX "WardenFeedIoc_host_idx" ON "WardenFeedIoc"("host");
CREATE INDEX "WardenFeedIoc_kind_idx" ON "WardenFeedIoc"("kind");

CREATE TABLE "WardenIocHit" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "iocValue" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "surface" TEXT NOT NULL,
    "subject" TEXT,
    "mailbox" TEXT,
    "detail" TEXT,
    "reportId" TEXT,
    "notified" BOOLEAN NOT NULL DEFAULT false,
    "ts" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenIocHit_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "WardenIocHit_ts_idx" ON "WardenIocHit"("ts");
CREATE INDEX "WardenIocHit_iocValue_idx" ON "WardenIocHit"("iocValue");
CREATE INDEX "WardenIocHit_notified_idx" ON "WardenIocHit"("notified");
