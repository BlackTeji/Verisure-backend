CREATE TABLE IF NOT EXISTS "user_email_aliases" (
    "id"                      TEXT        NOT NULL,
    "userId"                  TEXT        NOT NULL,
    "email"                   TEXT        NOT NULL,
    "verifiedAt"              TIMESTAMP(3),
    "verificationTokenHash"   TEXT,
    "verificationExpiresAt"   TIMESTAMP(3),
    "linkedCredentialCount"   INTEGER     NOT NULL DEFAULT 0,
    "createdAt"               TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_email_aliases_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "user_email_aliases_email_key"
    ON "user_email_aliases"("email");

CREATE INDEX IF NOT EXISTS "user_email_aliases_userId_verifiedAt_idx"
    ON "user_email_aliases"("userId", "verifiedAt");

ALTER TABLE "user_email_aliases"
    DROP CONSTRAINT IF EXISTS "user_email_aliases_userId_fkey";

ALTER TABLE "user_email_aliases"
    ADD CONSTRAINT "user_email_aliases_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;