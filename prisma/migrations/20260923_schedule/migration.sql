-- Scheduling state, so the cadence can live in Settings instead of a systemd timer.
--
-- Six hours is far too slow for a phishing queue. A single fast timer now calls tick.ts,
-- which reads the configured interval for each job and runs only what is due — so an
-- admin can change "check for new reports every 5 minutes" from the UI without root.

CREATE TABLE "WardenScheduleState" (
    "key" TEXT NOT NULL,
    "lastRunAt" TIMESTAMP(3),
    "lastOk" BOOLEAN NOT NULL DEFAULT true,
    "lastDetail" TEXT,
    "running" BOOLEAN NOT NULL DEFAULT false,
    "startedAt" TIMESTAMP(3),
    "runCount" INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "WardenScheduleState_pkey" PRIMARY KEY ("key")
);
