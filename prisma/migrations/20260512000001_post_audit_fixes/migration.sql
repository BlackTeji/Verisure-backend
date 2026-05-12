CREATE INDEX IF NOT EXISTS "verification_logs_credentialId_verifiedAt_idx"
    ON "verification_logs" ("credentialId", "verifiedAt" DESC);

ALTER TABLE "audit_logs" ALTER COLUMN "actorIp" DROP NOT NULL;

ALTER TABLE "credentials" ALTER COLUMN "id" SET DEFAULT gen_random_uuid()::text;

CREATE INDEX IF NOT EXISTS "blocked_ips_expiresAt_idx"
    ON "blocked_ips" ("expiresAt")
    WHERE "expiresAt" IS NOT NULL;