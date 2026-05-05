import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../../lib/db.js'
import { generateApiKey, generateWebhookSecret, encrypt, sha256 } from '../../lib/crypto.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireVerifier } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { redis, keys } from '../../lib/redis.js'

export default async function verifierRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireVerifier)

    // ── PROFILE ───────────────────────────────────────────────────
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

    // ── API KEYS ──────────────────────────────────────────────────
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

    // ── WEBHOOKS ──────────────────────────────────────────────────
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

    // ── VERIFICATION HISTORY ──────────────────────────────────────
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

    // ── USAGE ─────────────────────────────────────────────────────
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
}