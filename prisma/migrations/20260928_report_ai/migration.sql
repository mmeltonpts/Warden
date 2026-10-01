-- Claude triage results on a report.
--
-- Advisory only: nothing here gates a sweep, a lock or a state change. aiRanBy records
-- which human asked for the opinion, because "the console said it was phishing" must
-- always resolve to a person who pressed a button.
--
-- Stored rather than recomputed: the CLI session expires, the model is not deterministic,
-- and two analysts comparing notes at 22:00 must be looking at the same words.

ALTER TABLE "WardenReport" ADD COLUMN "aiVerdict" TEXT;
ALTER TABLE "WardenReport" ADD COLUMN "aiStatus" TEXT;
ALTER TABLE "WardenReport" ADD COLUMN "aiRanAt" TIMESTAMP(3);
ALTER TABLE "WardenReport" ADD COLUMN "aiRanBy" TEXT;
