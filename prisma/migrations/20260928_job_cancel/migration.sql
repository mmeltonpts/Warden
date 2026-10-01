-- Let an operator withdraw a queued job.
--
-- The worker runs one job at a time, so a sweep queued by mistake sat behind whatever was
-- running with no way to stop it from the console — `grep -rn "cancel|abort|stop|undo"`
-- across src/app returned nothing.
--
-- QUEUED only, deliberately. Killing GAM partway through a SWEEP would leave an unknown
-- number of messages trashed and no way to establish which, which is worse than either
-- outcome it sits between.

ALTER TYPE "WardenJobStatus" ADD VALUE IF NOT EXISTS 'CANCELLED';
