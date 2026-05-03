import Fastify from 'fastify'
import FastifyCors from '@fastify/cors'
import FastifyHelmet from '@fastify/helmet'
import FastifyRateLimit from '@fastify/rate-limit'
import FastifySwagger from '@fastify/swagger'
import FastifySwaggerUi from '@fastify/swagger-ui'
import FastifyCookie from '@fastify/cookie'
import { env } from './config/env.js'
import { redis } from './lib/redis.js'
import { logger } from './lib/logger.js'
import { db } from './lib/db.js'
import { checkBlockedIp, syncBlockedIpsFromDb } from './hooks/rate-limit.js'

import authRoutes from './routes/auth/index.js'
import credentialRoutes from './routes/credentials/index.js'
import issuerRoutes from './routes/issuers/index.js'
import holderRoutes from './routes/holders/index.js'
import verifierRoutes from './routes/verifiers/index.js'
import adminRoutes from './routes/admin/index.js'

const app = Fastify({
    logger: {
        level: env.LOG_LEVEL,
        redact: {
            paths: ['req.headers.authorization', 'req.headers.cookie', 'body.password', 'body.passwordHash'],
            censor: '[REDACTED]',
        },
    },
    trustProxy: true,
    requestTimeout: 30000,
    bodyLimit: 1_048_576,
})

// ── PLUGINS ───────────────────────────────────────────────────
await app.register(FastifyHelmet, {
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], scriptSrc: ["'none'"], styleSrc: ["'none'"], imgSrc: ["'none'"] } },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    noSniff: true,
    referrerPolicy: { policy: 'no-referrer' },
})

await app.register(FastifyCors, {
    origin: (origin, cb) => {
        if (!origin || env.ALLOWED_ORIGINS.includes(origin)) cb(null, true)
        else cb(new Error('Not allowed by CORS'), false)
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Requested-With'],
    credentials: true,
    maxAge: 600,
})

await app.register(FastifyCookie as any, { secret: env.JWT_REFRESH_SECRET })

await app.register(FastifyRateLimit, {
    global: true,
    max: env.RATE_LIMIT_PUBLIC_MAX,
    timeWindow: env.RATE_LIMIT_PUBLIC_WINDOW_MS,
    redis,
    keyGenerator: (req: any) => req.ip,
    errorResponseBuilder: (_req: any, ctx: any) => ({ error: 'Too many requests', message: `Retry after ${Math.round(ctx.ttl / 1000)}s`, retryAfter: Math.round(ctx.ttl / 1000) }),
})

if (env.NODE_ENV !== 'production') {
    await app.register(FastifySwagger, { openapi: { info: { title: 'VeriSure API', version: '1.0.0' }, servers: [{ url: env.API_BASE_URL }], components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } }, security: [{ bearerAuth: [] }] } })
    await app.register(FastifySwaggerUi, { routePrefix: '/api/docs' })
}

// ── GLOBAL HOOKS ──────────────────────────────────────────────
app.addHook('onSend', async (_req, reply) => {
    reply.header('X-Content-Type-Options', 'nosniff')
    reply.header('X-Frame-Options', 'DENY')
    reply.header('Cache-Control', 'no-store')
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
})

app.addHook('onRequest', checkBlockedIp)

// ── ROUTES ────────────────────────────────────────────────────
app.get('/api/health', async (_req, reply) => reply.status(200).send({ status: 'ok', timestamp: new Date().toISOString(), env: env.NODE_ENV }))

await app.register(authRoutes, { prefix: '/api/v1/auth' })
await app.register(credentialRoutes, { prefix: '/api/v1/credentials' })
await app.register(issuerRoutes, { prefix: '/api/v1/issuers' })
await app.register(holderRoutes, { prefix: '/api/v1/holders' })
await app.register(verifierRoutes, { prefix: '/api/v1/verifiers' })
await app.register(adminRoutes, { prefix: '/api/v1/admin' })


// ── ONE-TIME SEED ─────────────────────────────────────────────
// Remove this route after first successful seed
app.post('/api/seed', async (req, reply) => {
    const { token, password } = req.body as { token: string; password: string }
    if (token !== env.ADMIN_INITIAL_PASSWORD) {
        return reply.status(403).send({ error: 'Forbidden' })
    }
    const { scrypt, randomBytes } = await import('crypto')
    const { promisify } = await import('util')
    const scryptAsync = promisify(scrypt)
    const email = env.ADMIN_EMAIL ?? 'admin@verisure.ng'
    const existing = await db.user.findUnique({ where: { email } })
    if (existing) {
        return reply.status(200).send({ message: 'Admin already exists', email })
    }
    const salt = randomBytes(32).toString('hex')
    const key = await scryptAsync(password, salt, 64) as Buffer
    const passwordHash = salt + ':' + key.toString('hex')
    const user = await db.user.create({
        data: { email, passwordHash, role: 'ADMIN', firstName: 'VeriSure', lastName: 'Admin', emailVerified: true, isActive: true },
        select: { id: true, email: true }
    })
    return reply.status(201).send({ message: 'Admin created', email: user.email, id: user.id })
})

// ── ERROR HANDLERS ────────────────────────────────────────────
app.setNotFoundHandler((_req, reply) => reply.status(404).send({ error: 'Not found' }))

app.setErrorHandler((err, _req, reply) => {
    logger.error({ err }, 'unhandled error')
    if (env.NODE_ENV === 'production') return reply.status(500).send({ error: 'Internal server error' })
    const e = err as any; return reply.status(e.statusCode ?? 500).send({ error: e.name, message: e.message, stack: env.NODE_ENV === 'development' ? e.stack : undefined })
})

// ── STARTUP ───────────────────────────────────────────────────
async function start() {
    try {
        await db.$connect()
        logger.info('db: connected')

        // Run migrations programmatically — ensures tables exist before server starts
        const { execSync } = await import('child_process')
        try {
            execSync('npx prisma migrate deploy', { stdio: 'inherit' })
            logger.info('db: migrations applied')
        } catch (err) {
            logger.warn({ err }, 'db: migration failed — tables may already exist, continuing')
        }

        // Sync blocked IPs — non-fatal if tables missing
        try {
            await syncBlockedIpsFromDb()
        } catch (err) {
            logger.warn({ err }, 'startup: syncBlockedIps failed — continuing without blocked IP cache')
        }

        await app.listen({ port: env.PORT, host: env.HOST })
        logger.info(`server: listening on ${env.HOST}:${env.PORT}`)
    } catch (err) {
        logger.fatal({ err }, 'startup failed')
        process.exit(1)
    }
}

// ── SHUTDOWN ──────────────────────────────────────────────────
async function shutdown(signal: string) {
    logger.info({ signal }, 'shutting down')
    try { await app.close(); await db.$disconnect(); await redis.quit(); logger.info('shutdown complete'); process.exit(0) }
    catch (err) { logger.error({ err }, 'shutdown error'); process.exit(1) }
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))

start()