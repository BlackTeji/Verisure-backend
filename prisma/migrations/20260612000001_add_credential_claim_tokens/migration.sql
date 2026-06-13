ALTER TABLE "credentials" ADD COLUMN IF NOT EXISTS "claimTokenHash" TEXT;
ALTER TABLE "credentials" ADD COLUMN IF NOT EXISTS "claimTokenExpiresAt" TIMESTAMP(3);

CREATE UNIQUE INDEX IF NOT EXISTS "credentials_claimTokenHash_key"
    ON "credentials"("claimTokenHash");