-- SPAM as a triage outcome distinct from BENIGN.
--
-- BENIGN  = legitimate mail, misreported. Reassure the reporter.
-- SPAM    = junk that got through. No incident, but the sender is worth blocking.
--
-- Postgres 12+ permits ALTER TYPE ... ADD VALUE inside a transaction provided the new
-- value is not USED in that same transaction. Nothing here writes a SPAM row.

ALTER TYPE "WardenReportState" ADD VALUE IF NOT EXISTS 'SPAM';
