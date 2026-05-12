import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../../lib/db.js'
import { redis, keys } from '../../lib/redis.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireAdmin } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { blockIp, unblockIp } from '../../hooks/rate-limit.js'
import { getQueueHealth } from '../../lib/queue.js'
import { checkAnchorWalletBalance } from '../../lib/blockchain.js'
import { emailQueue } from '../../lib/queue.js'

export default async function adminRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireAdmin)

    // ── ISSUERS ───────────────────────────────────────────────────
    app.get('/issuers', async (req, reply) => {
        const query = z.object({
            status: z.enum(['PENDING', 'APPROVED', 'SUSPENDED', 'FROZEN']).optional(),
            page: z.coerce.number().int().min(1).default(1),
            limit: z.coerce.number().int().min(1).max(100).default(25),
            search: z.string().optional(),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { status, page, limit, search } = query.data
        const where: any = {
            ...(status ? { status } : {}),
            ...(search ? {
                OR: [
                    { institutionName: { contains: search, mode: 'insensitive' } },
                    { officialEmail: { contains: search, mode: 'insensitive' } },
                ]
            } : {}),
        }

        const [issuers, total] = await db.$transaction([
            db.issuerProfile.findMany({
                where,
                include: { user: { select: { email: true, createdAt: true, lastLoginAt: true, emailVerified: true } }, _count: { select: { credentials: true } } },
                orderBy: { createdAt: 'desc' },
                skip: (page - 1) * limit,
                take: limit,
            }),
            db.issuerProfile.count({ where }),
        ])

        return reply.status(200).send({ issuers, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    app.patch('/issuers/:id/approve', async (req, reply) => {
        const { id } = req.params as { id: string }
        const issuer = await db.issuerProfile.findUnique({
            where: { id },
            include: { user: { select: { email: true, firstName: true, emailVerified: true } } },
        })
        if (!issuer) return reply.status(404).send({ error: 'Not found' })
        if (issuer.status !== 'PENDING') return reply.status(409).send({ error: 'Conflict', message: 'Not pending' })

        if (!issuer.user.emailVerified) {
            return reply.status(422).send({
                error: 'Unprocessable',
                message: 'Institution email not verified. Ask the applicant to verify their email before approval.',
            })
        }

        await db.issuerProfile.update({
            where: { id },
            data: { status: 'APPROVED', approvedAt: new Date(), approvedById: req.userId },
        })
        await redis.del(keys.issuerStatus(id))

        await emailQueue.add('issuer_approved', {
            type: 'issuer_approved',
            to: issuer.officialEmail,
            data: {
                contactName: `${issuer.contactFirstName} ${issuer.contactLastName}`,
                institutionName: issuer.institutionName,
                dashboardUrl: `${process.env['FRONTEND_URL']}/pages/dashboard-issuer.html`,
            },
        })

        audit({ action: 'ISSUER_APPROVED', req, targetType: 'issuer', targetId: id, metadata: { institutionName: issuer.institutionName } })

        return reply.status(200).send({ message: 'Issuer approved', issuerId: id })
    })

    app.patch('/issuers/:id/suspend', async (req, reply) => {
        const { id } = req.params as { id: string }
        const body = z.object({ reason: z.string().min(1).max(500) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error' })

        const issuer = await db.issuerProfile.findUnique({ where: { id } })
        if (!issuer) return reply.status(404).send({ error: 'Not found' })

        await db.issuerProfile.update({
            where: { id },
            data: { status: 'SUSPENDED', suspendedAt: new Date(), suspendedReason: body.data.reason },
        })
        await redis.del(keys.issuerStatus(id))

        audit({ action: 'ISSUER_SUSPENDED', req, targetType: 'issuer', targetId: id, metadata: { reason: body.data.reason } })

        return reply.status(200).send({ message: 'Issuer suspended', issuerId: id })
    })

    // ── USERS ─────────────────────────────────────────────────────
    app.get('/users', async (req, reply) => {
        const query = z.object({
            role: z.enum(['HOLDER', 'ISSUER', 'VERIFIER', 'ADMIN']).optional(),
            page: z.coerce.number().int().min(1).default(1),
            limit: z.coerce.number().int().min(1).max(100).default(25),
            search: z.string().optional(),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { role, page, limit, search } = query.data
        const where: any = {
            ...(role ? { role } : {}),
            ...(search ? {
                OR: [
                    { email: { contains: search, mode: 'insensitive' } },
                    { firstName: { contains: search, mode: 'insensitive' } },
                    { lastName: { contains: search, mode: 'insensitive' } },
                ]
            } : {}),
        }

        const [users, total] = await db.$transaction([
            db.user.findMany({
                where,
                select: { id: true, email: true, role: true, firstName: true, lastName: true, isActive: true, isSuspended: true, emailVerified: true, createdAt: true, lastLoginAt: true },
                orderBy: { createdAt: 'desc' },
                skip: (page - 1) * limit,
                take: limit,
            }),
            db.user.count({ where }),
        ])

        return reply.status(200).send({ users, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    app.patch('/users/:id/suspend', async (req, reply) => {
        const { id } = req.params as { id: string }
        const body = z.object({ reason: z.string().min(1).max(500) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error' })
        if (id === req.userId) return reply.status(400).send({ error: 'Bad request', message: 'Cannot suspend yourself' })

        await db.user.update({ where: { id }, data: { isSuspended: true, suspendedAt: new Date(), suspendedReason: body.data.reason } })
        audit({ action: 'USER_SUSPENDED', req, targetType: 'user', targetId: id, metadata: { reason: body.data.reason } })

        return reply.status(200).send({ message: 'User suspended', userId: id })
    })

    // ── AUDIT LOGS ────────────────────────────────────────────────
    app.get('/audit', async (req, reply) => {
        const query = z.object({
            page: z.coerce.number().int().min(1).default(1),
            limit: z.coerce.number().int().min(1).max(100).default(50),
            action: z.string().optional(),
            actorId: z.string().optional(),
            targetType: z.string().optional(),
            targetId: z.string().optional(),
            from: z.string().datetime().optional(),
            to: z.string().datetime().optional(),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit, action, actorId, targetType, targetId, from, to } = query.data
        const where: any = {
            ...(action ? { action } : {}),
            ...(actorId ? { actorId } : {}),
            ...(targetType ? { targetType } : {}),
            ...(targetId ? { targetId } : {}),
            ...(from || to ? { createdAt: { ...(from ? { gte: new Date(from) } : {}), ...(to ? { lte: new Date(to) } : {}) } } : {}),
        }

        const [logs, total] = await db.$transaction([
            db.auditLog.findMany({ where, orderBy: { createdAt: 'desc' }, skip: (page - 1) * limit, take: limit }),
            db.auditLog.count({ where }),
        ])

        return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    // ── FRAUD ALERTS ──────────────────────────────────────────────
    app.get('/fraud-alerts', async (req, reply) => {
        const query = z.object({
            status: z.enum(['ACTIVE', 'RESOLVED', 'DISMISSED']).optional(),
            severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
            page: z.coerce.number().int().min(1).default(1),
            limit: z.coerce.number().int().min(1).max(100).default(25),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { status, severity, page, limit } = query.data
        const where: any = { ...(status ? { status } : {}), ...(severity ? { severity } : {}) }

        const [alerts, total] = await db.$transaction([
            db.fraudAlert.findMany({ where, orderBy: { createdAt: 'desc' }, skip: (page - 1) * limit, take: limit }),
            db.fraudAlert.count({ where }),
        ])

        return reply.status(200).send({ alerts, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    app.patch('/fraud-alerts/:id/resolve', async (req, reply) => {
        const { id } = req.params as { id: string }
        const body = z.object({ note: z.string().optional() }).safeParse(req.body)
        await db.fraudAlert.update({
            where: { id },
            data: { status: 'RESOLVED', resolvedAt: new Date(), resolvedById: req.userId, resolvedNote: body.success ? (body.data.note ?? null) : null },
        })
        audit({ action: 'FRAUD_ALERT_RESOLVED', req, targetType: 'fraud_alert', targetId: id })
        return reply.status(200).send({ message: 'Alert resolved' })
    })

    app.post('/fraud-alerts/:id/block-ip', async (req, reply) => {
        const { id } = req.params as { id: string }
        const body = z.object({ permanent: z.boolean().default(false) }).safeParse(req.body)
        const alert = await db.fraudAlert.findUnique({ where: { id }, select: { ipAddress: true } })
        if (!alert?.ipAddress) return reply.status(404).send({ error: 'No IP on this alert' })

        const ttl = body.success && !body.data.permanent ? 86_400 : undefined
        await blockIp(alert.ipAddress, `Admin block — alert ${id}`, ttl)
        await db.fraudAlert.update({ where: { id }, data: { status: 'RESOLVED', resolvedAt: new Date(), resolvedById: req.userId, resolvedNote: 'IP blocked' } })

        audit({ action: 'IP_BLOCKED', req, metadata: { ip: alert.ipAddress, permanent: !ttl, alertId: id } })

        return reply.status(200).send({ message: `IP ${alert.ipAddress} blocked`, permanent: !ttl })
    })

    app.delete('/blocked-ips/:ip', async (req, reply) => {
        const { ip } = req.params as { ip: string }
        await unblockIp(ip)
        return reply.status(200).send({ message: `IP ${ip} unblocked` })
    })

    // ── ANALYTICS ─────────────────────────────────────────────────
    app.get('/analytics', async (req, reply) => {
        const [
            totalCredentials, totalVerifications, totalUsers,
            activeIssuers, credsByStatus, last24h,
            topIssuers, topVerifiers,
        ] = await Promise.all([
            db.credential.count(),
            db.verificationLog.count(),
            db.user.count(),
            db.issuerProfile.count({ where: { status: 'APPROVED' } }),
            db.credential.groupBy({ by: ['status'], _count: true }),
            db.verificationLog.count({ where: { verifiedAt: { gte: new Date(Date.now() - 86_400_000) } } }),
            db.issuerProfile.findMany({ where: { status: 'APPROVED' }, include: { _count: { select: { credentials: true } } }, orderBy: { credentials: { _count: 'desc' } }, take: 10 }),
            db.verifierProfile.findMany({ include: { _count: { select: { verifications: true } } }, orderBy: { verifications: { _count: 'desc' } }, take: 10 }),
        ])

        return reply.status(200).send({
            totals: { credentials: totalCredentials, verifications: totalVerifications, users: totalUsers, activeIssuers, last24hVerifications: last24h },
            credentialsByStatus: Object.fromEntries(credsByStatus.map(c => [c.status, c._count])),
            topIssuers: topIssuers.map(i => ({ name: i.institutionName, count: i._count.credentials })),
            topVerifiers: topVerifiers.map(v => ({ name: v.organisationName, count: v._count.verifications })),
        })
    })

    // ── HEALTH ────────────────────────────────────────────────────
    app.get('/health', async (req, reply) => {
        const [queueHealth, walletBalance] = await Promise.all([
            getQueueHealth(),
            checkAnchorWalletBalance().catch(err => ({ error: String(err) })),
        ])

        let dbStatus: 'ok' | 'error' = 'ok'
        try { await db.$queryRaw`SELECT 1` } catch { dbStatus = 'error' }

        let redisStatus: 'ok' | 'error' = 'ok'
        try { await redis.ping() } catch { redisStatus = 'error' }

        return reply.status(200).send({
            timestamp: new Date().toISOString(),
            services: { database: dbStatus, redis: redisStatus },
            queues: queueHealth,
            blockchain: walletBalance,
        })
    })
}