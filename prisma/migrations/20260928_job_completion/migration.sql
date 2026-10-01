-- Make an incomplete GAM run distinguishable from a successful one.
--
-- Until now `runOne` set status = DONE unconditionally, and exitCode/timedOut were
-- computed and never rendered anywhere. The consequences were:
--
--   * a SCOPE that GAM aborted after 12 of 1,363 mailboxes showed a green DONE,
--     "12 messages across 4 mailboxes", and a live "Trash 12 messages" button;
--   * a VERIFY whose GAM was killed at the timeout parsed to zero rows and printed
--     "Verified clean — nothing remains outside Trash", writing verified = true to the
--     audit log.
--
-- An empty result and a failed result are not the same thing, and the console must never
-- again render the second as the first.

ALTER TABLE "WardenJob" ADD COLUMN "timedOut" BOOLEAN NOT NULL DEFAULT false;

ALTER TYPE "WardenJobStatus" ADD VALUE IF NOT EXISTS 'INCOMPLETE';
