-- Country an alert's IP is registered in, from RDAP.
--
-- RDAP has always returned it and WardenNetwork has always cached it; nothing read it. The
-- ingest could therefore auto-file a suspicious login from a foreign residential ISP as
-- benign, because it asked "is this a home connection?" and never "in which country?".

ALTER TABLE "WardenAlert" ADD COLUMN "ipCountry" TEXT;
