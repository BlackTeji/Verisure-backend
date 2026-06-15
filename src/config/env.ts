import 'dotenv/config'
import { z } from 'zod'

const schema = z.object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().default(3000),
    HOST: z.string().default('0.0.0.0'),
    API_BASE_URL: z.string().url(),
    FRONTEND_URL: z.string().url(),
    ALLOWED_ORIGINS: z.string().transform(s => s.split(',')),

    DATABASE_URL: z.string().url(),
    DATABASE_READ_URL: z.string().url().optional(),

    REDIS_URL: z.string(),
    REDIS_PASSWORD: z.string().optional(),

    JWT_ACCESS_SECRET: z.string().min(32),
    JWT_REFRESH_SECRET: z.string().min(32),
    JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN: z.string().default('30d'),

    API_KEY_ENCRYPTION_KEY: z.string()
        .length(64, 'API_KEY_ENCRYPTION_KEY must be 64 hex chars (32 bytes)')
        .regex(/^[0-9a-f]{64}$/, 'API_KEY_ENCRYPTION_KEY must be lowercase hex only'),

    ENCRYPTION_KEY: z.string()
        .length(64, 'ENCRYPTION_KEY must be 64 hex chars (32 bytes)')
        .regex(/^[0-9a-f]{64}$/, 'ENCRYPTION_KEY must be lowercase hex only'),

    POLYGON_RPC_URL: z.string().url(),
    POLYGON_ANCHOR_CONTRACT: z.string(),
    POLYGON_PRIVATE_KEY: z.string(),
    POLYGON_MIN_BALANCE: z.coerce.number().default(0.1),
    POLYGON_NETWORK: z.string().optional(),

    SMTP_HOST: z.string(),
    SMTP_PORT: z.coerce.number(),
    SMTP_SECURE: z.string().transform(s => s === 'true'),
    SMTP_USER: z.string(),
    SMTP_PASSWORD: z.string(),
    EMAIL_REPLY_TO: z.string().optional(),

    S3_BUCKET: z.string().min(1).optional(),
    S3_REGION: z.string().min(1).optional(),
    S3_ENDPOINT: z.string().url().optional(),
    S3_ACCESS_KEY_ID: z.string().min(1).optional(),
    S3_SECRET_ACCESS_KEY: z.string().min(1).optional(),

    RATE_LIMIT_PUBLIC_MAX: z.coerce.number().default(20),
    RATE_LIMIT_PUBLIC_WINDOW_MS: z.coerce.number().default(60000),
    RATE_LIMIT_AUTH_MAX: z.coerce.number().default(5),
    RATE_LIMIT_AUTH_WINDOW_MS: z.coerce.number().default(900000),
    RATE_LIMIT_API_MAX: z.coerce.number().default(100),
    RATE_LIMIT_API_WINDOW_MS: z.coerce.number().default(60000),

    FRAUD_RATE_THRESHOLD: z.coerce.number().default(15),
    FRAUD_RATE_WINDOW_SECONDS: z.coerce.number().default(60),
    FRAUD_AUTO_BLOCK: z.string().transform(s => s === 'true').default('true'),

    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
    LOG_PRETTY: z.string().transform(s => s === 'true').default('false'),

    ADMIN_EMAIL: z.string().email().optional(),
    ADMIN_INITIAL_PASSWORD: z.string().optional(),

    RESEND_API_KEY: z.string().min(1),
    EMAIL_FROM: z.string().email().or(z.string().regex(/^.+<.+@.+>$/)),
})

const parsed = schema.safeParse(process.env)

if (!parsed.success) {
    console.error('\n❌  Invalid environment:')
    parsed.error.issues.forEach(i => console.error(`   ${i.path.join('.')} — ${i.message}`))
    process.exit(1)
}

export const env = parsed.data
export type Env = typeof env