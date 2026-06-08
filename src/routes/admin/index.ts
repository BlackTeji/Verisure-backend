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
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { env } from '../../config/env.js'

export default async function adminRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireAdmin)

    // ── ISSUERS — LIST ────────────────────────────────────────────────────────

    app.get('/issuers', async (req, reply) => {
        const query = z.object({
            status: z.enum(['PENDING', 'UNDER_REVIEW', 'APPROVED', 'SUSPENDED', 'FROZEN']).optional(),
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
                include: {
                    user: { select: { email: true, createdAt: true, lastLoginAt: true, emailVerified: true } },
                    _count: { select: { credentials: true, documents: true } },
                },
                orderBy: { createdAt: 'desc' },
                skip: (page - 1) * limit,
                take: limit,
            }),
            db.issuerProfile.count({ where }),
        ])

        return reply.status(200).send({ issuers, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    // ── ISSUERS — DETAIL ──────────────────────────────────────────────────────

    app.get('/issuers/:id', async (req, reply) => {
        const { id } = req.params as { id: string }

        const profile = await db.issuerProfile.findUnique({
            where: { id },
            include: {
                user: { select: { id: true, email: true, firstName: true, lastName: true, emailVerified: true, createdAt: true, lastLoginAt: true } },
                documents: {
                    select: {
                        id: true, documentType: true, filename: true, mimeType: true,
                        fileSizeBytes: true, reviewStatus: true, reviewNote: true,
                        reviewedAt: true, virusScanStatus: true, uploadedAt: true,
                    },
                    orderBy: { uploadedAt: 'asc' },
                },
                messages: {
                    select: { id: true, direction: true, body: true, readAt: true, createdAt: true },
                    orderBy: { createdAt: 'asc' },
                },
                _count: { select: { credentials: true } },
            },
        })
        if (!profile) return reply.status(404).send({ error: 'Not found' })

        // Never expose the encrypted NIN value
        const safeProfile = {
            ...profile,
            signatoryNin: profile.signatoryNin ? 'XXX-XXXX-XXXXX (encrypted)' : null,
        }

        return reply.status(200).send({ profile: safeProfile })
    })

    // ── ISSUERS — DOCUMENT PRESIGNED URL ─────────────────────────────────────

    app.get('/issuers/:id/documents/:docId/url', async (req, reply) => {
        const { id, docId } = req.params as { id: string; docId: string }

        const doc = await db.issuerDocument.findFirst({ where: { id: docId, issuerId: id } })
        if (!doc) return reply.status(404).send({ error: 'Not found' })

        // 15-minute presigned URL
        const s3 = new S3Client({
            region: env.S3_REGION ?? 'auto',
            endpoint: env.S3_ENDPOINT,
            forcePathStyle: false,
        })
        const url = await getSignedUrl(
            s3,
            new GetObjectCommand({ Bucket: env.S3_BUCKET, Key: doc.storageKey }),
            { expiresIn: 900 },
        )

        audit({
            action: 'ADMIN_DOCUMENT_ACCESSED',
            req,
            targetType: 'issuer_document',
            targetId: doc.id,
            metadata: { issuerId: id, documentType: doc.documentType },
        })

        return reply.status(200).send({ url, expiresIn: 900 })
    })

    // ── ISSUERS — DOCUMENT REVIEW ─────────────────────────────────────────────

    app.patch('/issuers/:id/documents/:docId', async (req, reply) => {
        const { id, docId } = req.params as { id: string; docId: string }

        const body = z.object({
            reviewStatus: z.enum(['APPROVED', 'NEEDS_RESUBMISSION', 'REJECTED']),
            reviewNote: z.string().optional(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const { reviewStatus, reviewNote } = body.data

        if ((reviewStatus === 'NEEDS_RESUBMISSION' || reviewStatus === 'REJECTED') && !reviewNote?.trim()) {
            return reply.status(400).send({
                error: 'Validation error',
                message: 'A review note is required when returning or rejecting a document.',
            })
        }

        const doc = await db.issuerDocument.findFirst({ where: { id: docId, issuerId: id } })
        if (!doc) return reply.status(404).send({ error: 'Not found' })

        const updated = await db.issuerDocument.update({
            where: { id: docId },
            data: {
                reviewStatus: reviewStatus as any,
                reviewNote: reviewNote?.trim() ?? null,
                reviewedAt: new Date(),
                reviewedById: req.userId,
            },
        })

        audit({
            action: `DOCUMENT_${reviewStatus}` as any,
            req,
            targetType: 'issuer_document',
            targetId: doc.id,
            metadata: { issuerId: id, documentType: doc.documentType, reviewNote },
        })

        // Create an onboarding message if resubmission is needed
        if (reviewStatus === 'NEEDS_RESUBMISSION') {
            await db.onboardingMessage.create({
                data: {
                    issuerId: id,
                    fromAdminId: req.userId,
                    direction: 'ADMIN_TO_ISSUER',
                    body: `Your ${doc.documentType.replace(/_/g, ' ')} requires resubmission: ${reviewNote}`,
                },
            })
        }

        return reply.status(200).send({ document: updated })
    })

    // ── ISSUERS — APPROVE ─────────────────────────────────────────────────────

    app.patch('/issuers/:id/approve', async (req, reply) => {
        const { id } = req.params as { id: string }

        const profile = await db.issuerProfile.findUnique({
            where: { id },
            include: {
                documents: true,
                user: { select: { email: true, firstName: true, emailVerified: true } },
            },
        })
        if (!profile) return reply.status(404).send({ error: 'Not found' })

        if (profile.status === 'APPROVED') {
            return reply.status(409).send({ error: 'Conflict', message: 'Issuer is already approved.' })
        }

        if (!profile.user.emailVerified) {
            return reply.status(422).send({
                error: 'Unprocessable',
                message: 'Institution email not verified. Ask the applicant to verify their email before approval.',
            })
        }

        // CAC Certificate must be present and approved
        const cacDoc = profile.documents.find((d: any) => d.documentType === 'CAC_CERTIFICATE')
        if (!cacDoc || cacDoc.reviewStatus !== 'APPROVED') {
            return reply.status(400).send({
                error: 'Prerequisite failed',
                message: 'CAC Certificate must be uploaded and approved before approving the issuer.',
            })
        }

        // Signatory details must be complete
        if (!profile.signatoryNin || !profile.signatoryWorkEmail) {
            return reply.status(400).send({
                error: 'Prerequisite failed',
                message: 'Signatory NIN and work email must be on file before approval.',
            })
        }

        await db.issuerProfile.update({
            where: { id },
            data: {
                status: 'APPROVED',
                approvedAt: new Date(),
                approvedById: req.userId,
                twoFactorRequired: true,
            },
        })
        await redis.del(keys.issuerStatus(id))

        await emailQueue.add('issuer_approved', {
            type: 'issuer_approved',
            to: profile.officialEmail,
            data: {
                contactName: `${profile.contactFirstName} ${profile.contactLastName}`,
                institutionName: profile.institutionName,
                dashboardUrl: `${env.FRONTEND_URL}/pages/dashboard-issuer.html`,
            },
        })

        audit({ action: 'ISSUER_APPROVED', req, targetType: 'issuer', targetId: id, metadata: { institutionName: profile.institutionName } })

        return reply.status(200).send({ message: 'Issuer approved', issuerId: id })
    })

    // ── ISSUERS — REJECT / RETURN TO PENDING ─────────────────────────────────

    app.post('/issuers/:id/reject', async (req, reply) => {
        const { id } = req.params as { id: string }

        const body = z.object({ reason: z.string().min(1).max(1000) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const profile = await db.issuerProfile.findUnique({ where: { id } })
        if (!profile) return reply.status(404).send({ error: 'Not found' })

        await db.$transaction([
            db.issuerProfile.update({
                where: { id },
                data: { status: 'PENDING' },
            }),
            db.onboardingMessage.create({
                data: {
                    issuerId: id,
                    fromAdminId: req.userId,
                    direction: 'ADMIN_TO_ISSUER',
                    body: body.data.reason.trim(),
                },
            }),
        ])

        audit({
            action: 'ISSUER_APPLICATION_REJECTED',
            req,
            targetType: 'issuer',
            targetId: id,
            metadata: { reason: body.data.reason },
        })

        return reply.status(200).send({ message: 'Application returned to issuer.' })
    })

    // ── ISSUERS — SUSPEND ─────────────────────────────────────────────────────

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

    // ── ISSUERS — MESSAGE (admin → issuer) ────────────────────────────────────

    app.post('/issuers/:id/message', async (req, reply) => {
        const { id } = req.params as { id: string }

        const body = z.object({ message: z.string().min(1).max(2000) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const profile = await db.issuerProfile.findUnique({ where: { id } })
        if (!profile) return reply.status(404).send({ error: 'Not found' })

        const msg = await db.onboardingMessage.create({
            data: {
                issuerId: id,
                fromAdminId: req.userId,
                direction: 'ADMIN_TO_ISSUER',
                body: body.data.message.trim(),
            },
        })

        return reply.status(201).send({ message: msg })
    })

    // ── USERS ─────────────────────────────────────────────────────────────────

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

    // ── AUDIT LOGS ────────────────────────────────────────────────────────────

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

    // ── FRAUD ALERTS ──────────────────────────────────────────────────────────

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

    // ── ANALYTICS ─────────────────────────────────────────────────────────────

    app.get('/analytics', async (req, reply) => {
        const [
            totalCredentials, totalVerifications, totalUsers,
            activeIssuers, pendingReview, credsByStatus, last24h,
            topIssuers, topVerifiers,
        ] = await Promise.all([
            db.credential.count(),
            db.verificationLog.count(),
            db.user.count(),
            db.issuerProfile.count({ where: { status: 'APPROVED' } }),
            db.issuerProfile.count({ where: { status: 'UNDER_REVIEW' } }),
            db.credential.groupBy({ by: ['status'], _count: true }),
            db.verificationLog.count({ where: { verifiedAt: { gte: new Date(Date.now() - 86_400_000) } } }),
            db.issuerProfile.findMany({ where: { status: 'APPROVED' }, include: { _count: { select: { credentials: true } } }, orderBy: { credentials: { _count: 'desc' } }, take: 10 }),
            db.verifierProfile.findMany({ include: { _count: { select: { verifications: true } } }, orderBy: { verifications: { _count: 'desc' } }, take: 10 }),
        ])

        return reply.status(200).send({
            totals: { credentials: totalCredentials, verifications: totalVerifications, users: totalUsers, activeIssuers, pendingReview, last24hVerifications: last24h },
            credentialsByStatus: Object.fromEntries(credsByStatus.map(c => [c.status, c._count])),
            topIssuers: topIssuers.map(i => ({ name: i.institutionName, count: i._count.credentials })),
            topVerifiers: topVerifiers.map(v => ({ name: v.organisationName, count: v._count.verifications })),
        })
    })

    // ── HEALTH ────────────────────────────────────────────────────────────────

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