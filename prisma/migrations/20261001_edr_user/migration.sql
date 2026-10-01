-- Attribute SYSTEM-context endpoint alerts to the person signed in to the host at the time.
ALTER TABLE "WardenEdrAlert" ADD COLUMN "userSource" TEXT;
ALTER TABLE "WardenEdrAlert" ADD COLUMN "loginUser" TEXT;
ALTER TABLE "WardenEdrAlert" ADD COLUMN "loginAt" TIMESTAMP(3);
