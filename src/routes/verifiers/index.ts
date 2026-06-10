import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { scrypt, randomBytes } from 'node:crypto'
import { promisify } from 'node:util'
import { db } from '../../lib/db.js'
import { generateApiKey, generateWebhookSecret, encrypt, sha256 } from '../../lib/crypto.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireVerifier } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { redis, keys } from '../../lib/redis.js'
import { webhookQueue, bulkQueue } from '../../lib/queue.js'
import { revokeAllUserTokens } from '../../lib/jwt.js'

const scryptAsync = promisify(scrypt)

// ── PASSWORD HELPERS ─────────────────────────────────────────────────

async function verifyPwd(input: string, stored: string): Promise<boolean> {
    const [salt, hash] = stored.split(':')
    if (!salt || !hash) return false
    const key = await scryptAsync(input, salt, 64) as Buffer
    const ref = Buffer.from(hash, 'hex')
    if (key.length !== ref.length) return false
    let diff = 0
    for (let i = 0; i < key.length; i++) diff |= (key[i] ?? 0) ^ (ref[i] ?? 0)
    return diff === 0
}

async function hashPwd(p: string): Promise<string> {
    const salt = randomBytes(32).toString('hex')
    const key = await scryptAsync(p, salt, 64) as Buffer
    return `${salt}:${key.toString('hex')}`
}

export default async function verifierRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireVerifier)

    // ── PROFILE ─────────────────────────────────────────────────────────
    app.get('/me', async (req, reply) => {
        const user = await db.user.findUnique({
            where: { id: req.userId! },
            select: {
                id: true, email: true, firstName: true, lastName: true, role: true, createdAt: true,
                verifierProfile: { select: { id: true, organisationName: true, organisationType: true, teamSize: true } }
            }
        })
        if (!user) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ user })
    })

    app.patch('/me', async (req, reply) => {
        const body = z.object({
            organisationName: z.string().min(1).max(200).optional(),
            organisationType: z.string().max(100).optional(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
        const profile = await db.verifierProfile.update({
            where: { id: req.verifierId! },
            data: body.data,
            select: { id: true, organisationName: true, organisationType: true }
        })
        return reply.status(200).send({ profile })
    })

    // ── API KEYS ────────────────────────────────────────────────────────
    app.get('/me/api-keys', async (req, reply) => {
        const apiKeys = await db.apiKey.findMany({ where: { verifierId: req.verifierId!, isActive: true }, select: { id: true, name: true, keyPrefix: true, environment: true, scopes: true, lastUsedAt: true, lastUsedIp: true, callCount: true, createdAt: true }, orderBy: { createdAt: 'desc' } })
        return reply.status(200).send({ apiKeys })
    })

    app.post('/me/api-keys', async (req, reply) => {
        const body = z.object({ name: z.string().min(1).max(100), environment: z.enum(['live', 'test']), scopes: z.array(z.enum(['verify', 'batch', 'issuer_lookup'])).min(1) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const count = await db.apiKey.count({ where: { verifierId: req.verifierId!, isActive: true } })
        if (count >= 5) return reply.status(429).send({ error: 'Limit exceeded', message: 'Max 5 API keys' })

        const { plaintext, hash: keyHash, prefix } = generateApiKey(body.data.environment)
        const apiKey = await db.apiKey.create({ data: { verifierId: req.verifierId!, name: body.data.name, keyHash, keyPrefix: prefix, environment: body.data.environment, scopes: body.data.scopes }, select: { id: true, name: true, keyPrefix: true, environment: true, scopes: true, createdAt: true } })

        audit({ action: 'API_KEY_CREATED', req, targetType: 'api_key', targetId: apiKey.id })

        return reply.status(201).send({ ...apiKey, key: plaintext, warning: 'This key will not be shown again. Store it securely.' })
    })

    app.delete('/me/api-keys/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const k = await db.apiKey.findUnique({ where: { id }, select: { verifierId: true, keyHash: true } })
        if (!k || k.verifierId !== req.verifierId) return reply.status(404).send({ error: 'Not found' })

        await db.apiKey.update({ where: { id }, data: { isActive: false, revokedAt: new Date() } })
        await redis.del(keys.apiKey(k.keyHash))
        audit({ action: 'API_KEY_REVOKED', req, targetType: 'api_key', targetId: id })

        return reply.status(200).send({ message: 'API key revoked' })
    })

    app.post('/me/api-keys/:id/rotate', async (req, reply) => {
        const { id } = req.params as { id: string }
        const old = await db.apiKey.findUnique({ where: { id }, select: { verifierId: true, name: true, environment: true, scopes: true, keyHash: true } })
        if (!old || old.verifierId !== req.verifierId) return reply.status(404).send({ error: 'Not found' })

        const env2 = old.environment as 'live' | 'test'
        const { plaintext, hash: keyHash, prefix } = generateApiKey(env2)

        const [, newKey] = await db.$transaction([
            db.apiKey.update({ where: { id }, data: { isActive: false, revokedAt: new Date() } }),
            db.apiKey.create({ data: { verifierId: req.verifierId!, name: old.name, keyHash, keyPrefix: prefix, environment: old.environment, scopes: old.scopes }, select: { id: true, name: true, keyPrefix: true, environment: true, scopes: true, createdAt: true } }),
        ])

        await redis.del(keys.apiKey(old.keyHash))
        audit({ action: 'API_KEY_ROTATED', req, targetType: 'api_key', targetId: id, metadata: { newKeyId: newKey.id } })

        return reply.status(201).send({ ...newKey, key: plaintext, warning: 'Update your integrations with this new key.' })
    })

    // ── WEBHOOKS ────────────────────────────────────────────────────────
    app.get('/me/webhooks', async (req, reply) => {
        const webhooks = await db.webhook.findMany({ where: { verifierId: req.verifierId! }, select: { id: true, name: true, url: true, events: true, isActive: true, lastDeliveredAt: true, failureCount: true, createdAt: true, deliveries: { take: 5, orderBy: { createdAt: 'desc' }, select: { success: true, statusCode: true, createdAt: true, event: true } } }, orderBy: { createdAt: 'desc' } })
        return reply.status(200).send({ webhooks })
    })

    app.post('/me/webhooks', async (req, reply) => {
        const body = z.object({ name: z.string().min(1).max(100), url: z.string().url().startsWith('https://'), events: z.array(z.enum(['credential.verified', 'credential.revoked', 'credential.frozen', 'credential.expired', 'issuer.suspended'])).min(1) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const count = await db.webhook.count({ where: { verifierId: req.verifierId! } })
        if (count >= 10) return reply.status(429).send({ error: 'Limit exceeded', message: 'Max 10 webhooks' })

        const secret = generateWebhookSecret()
        const secretHash = encrypt(secret)

        const webhook = await db.webhook.create({ data: { verifierId: req.verifierId!, name: body.data.name, url: body.data.url, secretHash, events: body.data.events }, select: { id: true, name: true, url: true, events: true, createdAt: true } })

        return reply.status(201).send({ ...webhook, secret, warning: 'Store this signing secret — it will not be shown again.' })
    })

    app.delete('/me/webhooks/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const w = await db.webhook.findUnique({ where: { id }, select: { verifierId: true } })
        if (!w || w.verifierId !== req.verifierId) return reply.status(404).send({ error: 'Not found' })
        await db.webhook.update({ where: { id }, data: { isActive: false } })
        return reply.status(200).send({ message: 'Webhook deleted' })
    })

    // ── WEBHOOK TEST DELIVERY ───────────────────────────────────────────
    app.post('/me/webhooks/:id/test', async (req, reply) => {
        const { id } = req.params as { id: string }

        const webhook = await db.webhook.findUnique({
            where: { id },
            select: { verifierId: true, isActive: true, url: true },
        })

        if (!webhook || webhook.verifierId !== req.verifierId) {
            return reply.status(404).send({ error: 'Not found' })
        }

        if (!webhook.isActive) {
            return reply.status(409).send({
                error: 'Webhook inactive',
                message: 'This webhook endpoint has been deleted and cannot receive test events.',
            })
        }

        const job = await webhookQueue.add(
            'test',
            {
                webhookId: id,
                event: 'test',
                payload: {
                    message: 'This is a test event from VeriSure.',
                    webhook_id: id,
                    endpoint_url: webhook.url,
                    sent_at: new Date().toISOString(),
                },
            },

            { attempts: 1, delay: 0, removeOnComplete: true, removeOnFail: true }
        )

        audit({ action: 'WEBHOOK_TEST_SENT', req, targetType: 'webhook', targetId: id })

        return reply.status(202).send({
            queued: true,
            jobId: job.id,
            message: 'Test event queued. Check your endpoint logs for the delivery.',
        })
    })

    // ── BULK VERIFICATION JOBS ──────────────────────────────────────────
    // POST creates a bulk verification job (the bulk worker already
    // handles type 'verification' — this route was the missing producer).
    // GET endpoints power the dashboard's bulk results display.

    app.post('/me/bulk-jobs', async (req, reply) => {
        const body = z.object({
            credential_ids: z.array(z.string().min(1).max(100)).min(1).max(10000),
            filename: z.string().max(200).optional(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        // One active job per verifier — mirrors issuer bulk constraint
        const activeJob = await db.bulkJob.findFirst({
            where: { verifierId: req.verifierId!, status: { in: ['PENDING', 'PROCESSING'] } },
            select: { id: true },
        })
        if (activeJob) {
            return reply.status(409).send({
                error: 'Conflict',
                message: 'A bulk verification job is already in progress. Wait for it to complete before starting another.',
            })
        }

        const rows = body.data.credential_ids.map(id => ({ credential_id: id }))

        const job = await db.bulkJob.create({
            data: {
                type: 'verification',
                verifierId: req.verifierId!,
                filename: body.data.filename ?? `bulk_verify_${Date.now()}.csv`,
                totalRows: rows.length,
                status: 'PENDING',
            },
        })

        await bulkQueue.add('bulk-verification', {
            jobId: job.id,
            type: 'verification',
            fileKey: JSON.stringify(rows),
            verifierId: req.verifierId!,
        })

        audit({ action: 'BULK_VERIFICATION_STARTED', req, targetType: 'bulk_job', targetId: job.id, metadata: { rows: rows.length } })

        return reply.status(202).send({ jobId: job.id, status: 'PENDING', rows: rows.length })
    })

    app.get('/me/bulk-jobs', async (req, reply) => {
        const jobs = await db.bulkJob.findMany({
            where: { verifierId: req.verifierId!, type: 'verification' },
            orderBy: { createdAt: 'desc' },
            take: 20,
        })
        return reply.status(200).send({ jobs })
    })

    app.get('/me/bulk-jobs/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const job = await db.bulkJob.findUnique({ where: { id } })
        if (!job || job.verifierId !== req.verifierId) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ job })
    })

    // ── VERIFICATION HISTORY ────────────────────────────────────────────
    app.get('/me/verifications', async (req, reply) => {
        const query = z.object({ page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(100).default(25), result: z.enum(['ACTIVE', 'REVOKED', 'FROZEN', 'EXPIRED']).optional(), method: z.enum(['DASHBOARD', 'QR_SCAN', 'API', 'BULK_CSV']).optional() }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit, result, method } = query.data
        const where: any = { verifierId: req.verifierId!, ...(result ? { result } : {}), ...(method ? { method } : {}) }

        const [logs, total] = await db.$transaction([
            db.verificationLog.findMany({ where, include: { credential: { select: { credentialType: true, holderName: true, issuer: { select: { institutionName: true } } } } }, orderBy: { verifiedAt: 'desc' }, skip: (page - 1) * limit, take: limit }),
            db.verificationLog.count({ where }),
        ])

        return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    // ── USAGE ───────────────────────────────────────────────────────────
    app.get('/me/usage', async (req, reply) => {
        const now = new Date()
        const monthStart = new Date(now.getFullYear(), now.getMonth(), 1)

        const [total, byResult, byMethod, apiKeys] = await Promise.all([
            db.verificationLog.count({ where: { verifierId: req.verifierId!, verifiedAt: { gte: monthStart } } }),
            db.verificationLog.groupBy({ by: ['result'], where: { verifierId: req.verifierId!, verifiedAt: { gte: monthStart } }, _count: true }),
            db.verificationLog.groupBy({ by: ['method'], where: { verifierId: req.verifierId!, verifiedAt: { gte: monthStart } }, _count: true }),
            db.apiKey.findMany({ where: { verifierId: req.verifierId!, isActive: true }, select: { name: true, keyPrefix: true, callCount: true, lastUsedAt: true } }),
        ])

        return reply.status(200).send({
            currentPeriod: {
                start: monthStart.toISOString(),
                verifications: total,
                byResult: Object.fromEntries(byResult.map(r => [r.result, r._count])),
                byMethod: Object.fromEntries(byMethod.map(m => [m.method, m._count])),
            },
            apiKeys,
        })
    })

    // ── PASSWORD CHANGE ─────────────────────────────────────────────────
    // Verifier passwords: minimum 8 characters per TRD §3.2.2.
    // All refresh tokens and sessions revoked on change.

    app.patch('/me/password', async (req, reply) => {
        const body = z.object({
            currentPassword: z.string(),
            newPassword: z.string().min(8).max(128),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { id: true, passwordHash: true } })
        if (!user) return reply.status(404).send({ error: 'Not found' })

        if (!await verifyPwd(body.data.currentPassword, user.passwordHash)) {
            return reply.status(401).send({ error: 'Unauthorized', message: 'Current password is incorrect' })
        }

        await db.user.update({ where: { id: req.userId! }, data: { passwordHash: await hashPwd(body.data.newPassword), failedLoginCount: 0 } })
        await revokeAllUserTokens(req.userId!)

        await db.userSession.updateMany({
            where: { userId: req.userId!, isActive: true },
            data: { isActive: false, revokedAt: new Date() },
        }).catch(() => { })

        audit({ action: 'USER_PASSWORD_CHANGED', req, targetType: 'user', targetId: req.userId! })

        return reply.status(200).send({ message: 'Password updated. Please log in again.' })
    })

    // ── SESSIONS ────────────────────────────────────────────────────────
    // Mirrors the holder session management pattern.

    app.get('/me/sessions', async (req, reply) => {
        const sessions = await db.userSession.findMany({
            where: { userId: req.userId!, isActive: true },
            select: { id: true, ipAddress: true, userAgent: true, country: true, city: true, lastSeenAt: true, createdAt: true },
            orderBy: { lastSeenAt: 'desc' },
        })
        return reply.status(200).send({ sessions })
    })

    app.delete('/me/sessions/:sessionId', async (req, reply) => {
        const { sessionId } = req.params as { sessionId: string }
        const s = await db.userSession.findUnique({ where: { id: sessionId }, select: { userId: true } })
        if (!s || s.userId !== req.userId) return reply.status(404).send({ error: 'Not found' })
        await db.userSession.update({ where: { id: sessionId }, data: { isActive: false, revokedAt: new Date() } })
        audit({ action: 'TOKEN_REVOKED', req, targetType: 'user_session', targetId: sessionId })
        return reply.status(200).send({ message: 'Session revoked' })
    })

    app.delete('/me/sessions', async (req, reply) => {
        await db.userSession.updateMany({ where: { userId: req.userId!, isActive: true }, data: { isActive: false, revokedAt: new Date() } })
        await revokeAllUserTokens(req.userId!)
        audit({ action: 'TOKEN_REVOKED', req, targetType: 'user', targetId: req.userId!, metadata: { scope: 'all_sessions' } })
        return reply.status(200).send({ message: 'All sessions revoked' })
    })
}