-- KnowBe4 mirror: local cache of the KSAT roster so it can be joined against Warden data.

CREATE TABLE "WardenKb4User" (
    "kb4Id" INTEGER NOT NULL,
    "email" TEXT NOT NULL,
    "firstName" TEXT,
    "lastName" TEXT,
    "jobTitle" TEXT,
    "department" TEXT,
    "division" TEXT,
    "location" TEXT,
    "managerEmail" TEXT,
    "employeeNumber" TEXT,
    "phishPronePct" DOUBLE PRECISION,
    "riskScore" DOUBLE PRECISION,
    "status" TEXT,
    "groupIds" TEXT NOT NULL DEFAULT '[]',
    "aliases" TEXT NOT NULL DEFAULT '[]',
    "provisioningManaged" BOOLEAN NOT NULL DEFAULT false,
    "joinedOn" TIMESTAMP(3),
    "lastSignIn" TIMESTAMP(3),
    "syncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenKb4User_pkey" PRIMARY KEY ("kb4Id")
);

CREATE UNIQUE INDEX "WardenKb4User_email_key" ON "WardenKb4User"("email");
CREATE INDEX "WardenKb4User_phishPronePct_idx" ON "WardenKb4User"("phishPronePct");
CREATE INDEX "WardenKb4User_department_idx" ON "WardenKb4User"("department");

CREATE TABLE "WardenKb4Account" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "name" TEXT NOT NULL,
    "subscriptionLevel" TEXT,
    "subscriptionEnds" TIMESTAMP(3),
    "seats" INTEGER,
    "riskScore" DOUBLE PRECISION,
    "admins" TEXT NOT NULL DEFAULT '[]',
    "userCount" INTEGER NOT NULL DEFAULT 0,
    "syncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastError" TEXT,
    CONSTRAINT "WardenKb4Account_pkey" PRIMARY KEY ("id")
);
