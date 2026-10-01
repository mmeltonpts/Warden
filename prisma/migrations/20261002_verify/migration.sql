-- Staff sign-in verification ("was this you?") and the student VPN notice queue.

CREATE TYPE "WardenVerifyState" AS ENUM ('SENT', 'CONFIRMED_YES', 'DENIED', 'HIDDEN', 'EXPIRED', 'ERROR');
CREATE TYPE "WardenStudentNoticeState" AS ENUM ('QUEUED', 'SENT', 'DISMISSED');

CREATE TABLE "WardenSignInVerify" (
    "id" TEXT NOT NULL,
    "mailbox" TEXT NOT NULL,
    "signInTs" TIMESTAMP(3) NOT NULL,
    "ip" TEXT,
    "geo" TEXT,
    "netOrg" TEXT,
    "score" INTEGER,
    "riskFlagId" TEXT,
    "code" TEXT NOT NULL,
    "rfcMessageId" TEXT,
    "sentAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "state" "WardenVerifyState" NOT NULL DEFAULT 'SENT',
    "checks" TEXT,
    "lastCheckedAt" TIMESTAMP(3),
    "replyAt" TIMESTAMP(3),
    "replyExcerpt" TEXT,
    "filterFound" TEXT,
    "closedAt" TIMESTAMP(3),
    "notes" TEXT,
    CONSTRAINT "WardenSignInVerify_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WardenSignInVerify_code_key" ON "WardenSignInVerify"("code");
CREATE INDEX "WardenSignInVerify_state_sentAt_idx" ON "WardenSignInVerify"("state", "sentAt");
CREATE INDEX "WardenSignInVerify_mailbox_idx" ON "WardenSignInVerify"("mailbox");

CREATE TABLE "WardenStudentVpnNotice" (
    "id" TEXT NOT NULL,
    "student" TEXT NOT NULL,
    "signInTs" TIMESTAMP(3) NOT NULL,
    "ip" TEXT,
    "geo" TEXT,
    "netOrg" TEXT,
    "ouPath" TEXT,
    "building" TEXT,
    "schoolHours" BOOLEAN NOT NULL DEFAULT false,
    "adminEmail" TEXT,
    "state" "WardenStudentNoticeState" NOT NULL DEFAULT 'QUEUED',
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "WardenStudentVpnNotice_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WardenStudentVpnNotice_student_signInTs_key" ON "WardenStudentVpnNotice"("student", "signInTs");
CREATE INDEX "WardenStudentVpnNotice_state_createdAt_idx" ON "WardenStudentVpnNotice"("state", "createdAt");
CREATE INDEX "WardenStudentVpnNotice_adminEmail_idx" ON "WardenStudentVpnNotice"("adminEmail");
