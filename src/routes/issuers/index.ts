import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../../lib/db.js'
import { redis, keys } from '../../lib/redis.js'
import { generateSecureToken, sha256, generateCredentialId, hashCredential } from '../../lib/crypto.js'
import { anchorQueue, emailQueue, bulkQueue } from '../../lib/queue.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireIssuer, requireApprovedIssuer } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { revokeAllUserTokens } from '../../lib/jwt.js'
import { env } from '../../config/env.js'
import { parseCsv } from '../../lib/csv.js'
import { isStrictIsoDateString } from '../../lib/dates.js'
import { createCipheriv, createHash, createHmac, randomBytes, scrypt } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)

const bulkRowSchema = z.object({
    holderName: z.string().min(1).max(200),
    holderEmail: z.string().email().toLowerCase(),
    credentialType: z.string().min(1).max(200),
    field: z.string().max(200).optional(),
    notes: z.string().max(1000).optional(),
    issueDate: z.string().min(1).refine(isStrictIsoDateString, {
        message: 'issueDate must be ISO 8601 format (YYYY-MM-DD), e.g. 2024-02-17. Ambiguous formats like 2/17/2024 are rejected.',
    }),
    expiryDate: z.string().optional().refine(v => v === undefined || isStrictIsoDateString(v), {
        message: 'expiryDate must be ISO 8601 format (YYYY-MM-DD).',
    }),
})

const MAX_BULK_ROWS = 10_000

export default async function issuerRoutes(app: FastifyInstance) {

    app.get('/public', async (request, reply) => {
        const query = z.object({
            page: z.coerce.number().int().positive().default(1),
            limit: z.coerce.number().int().min(1).max(100).default(48),
            search: z.string().max(120).optional(),
            type: z.string().max(80).optional(),
        }).safeParse(request.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })
        const { page, limit, search, type } = query.data
        const skip = (page - 1) * limit
        const where: any = { status: 'APPROVED' }
        if (search?.trim()) where.institutionName = { contains: search.trim(), mode: 'insensitive' }
        if (type?.trim()) where.institutionType = type.trim()
        const [issuers, total] = await Promise.all([
            db.issuerProfile.findMany({
                where, skip, take: limit, orderBy: { approvedAt: 'desc' },
                select: {
                    id: true, institutionName: true, institutionType: true,
                    websiteUrl: true, logoUrl: true, approvedAt: true,
                    _count: { select: { credentials: true } },
                },
            }),
            db.issuerProfile.count({ where }),
        ])
        return reply.send({ issuers, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    app.register(async function protectedIssuerRoutes(protectedApp) {

        protectedApp.addHook('preHandler', authenticate)
        protectedApp.addHook('preHandler', requireIssuer)

        protectedApp.get('/me', async (req, reply) => {
            const profile = await db.issuerProfile.findUnique({
                where: { userId: req.userId! },
                include: {
                    _count: { select: { credentials: true, teamMembers: true } },
                    whitelabelPortal: {
                        select: { id: true, customDomain: true, displayName: true, isLive: true, dnsVerified: true },
                    },
                    documents: {
                        select: { id: true, documentType: true, filename: true, reviewStatus: true, reviewNote: true, uploadedAt: true },
                        orderBy: { uploadedAt: 'asc' },
                    },
                    messages: {
                        where: { direction: 'ADMIN_TO_ISSUER' },
                        select: { id: true, direction: true, body: true, readAt: true, createdAt: true },
                        orderBy: { createdAt: 'asc' },
                    },
                },
            })
            if (!profile) return reply.status(404).send({ error: 'Not found' })
            const safeProfile = { ...profile, signatoryNin: profile.signatoryNin ? 'XXX-XXXX-XXXXX' : null }
            const user = await db.user.findUnique({ where: { id: req.userId! }, select: { twoFactorEnabled: true } })
            return reply.status(200).send({ profile: { ...safeProfile, twoFactorEnabled: user?.twoFactorEnabled ?? false } })
        })

        protectedApp.patch('/me', async (req, reply) => {
            const body = z.object({
                institutionName: z.string().max(200).optional(),
                institutionType: z.string().optional(),
                registrationNumber: z.string().optional(),
                phone: z.string().optional(),
                websiteUrl: z.string().url().optional(),
                contactFirstName: z.string().optional(),
                contactLastName: z.string().optional(),
                contactTitle: z.string().optional(),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const profile = await db.issuerProfile.update({
                where: { userId: req.userId! },
                data: body.data,
                select: { id: true, institutionName: true, institutionType: true, status: true },
            })
            return reply.status(200).send({ profile })
        })

        protectedApp.post('/onboarding/step/1', async (req, reply) => {
            const body = z.object({
                institutionName: z.string().min(1).max(200),
                institutionType: z.string().min(1),
                registrationNumber: z.string().optional(),
                contactFirstName: z.string().min(1),
                contactLastName: z.string().min(1),
                contactTitle: z.string().optional(),
                phone: z.string().optional(),
                websiteUrl: z.string().url().optional(),
                annualVolume: z.string().optional(),
                physicalAddress: z.object({
                    street: z.string().min(1),
                    lga: z.string().min(1),
                    state: z.string().min(1),
                    country: z.string().optional(),
                }),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! } })
            if (!profile) return reply.status(404).send({ error: 'Not found', message: 'Issuer profile not found.' })
            const d = body.data
            await db.issuerProfile.update({
                where: { userId: req.userId! },
                data: {
                    institutionName: d.institutionName.trim(),
                    institutionType: d.institutionType,
                    registrationNumber: d.registrationNumber?.trim() ?? undefined,
                    contactFirstName: d.contactFirstName.trim(),
                    contactLastName: d.contactLastName.trim(),
                    contactTitle: d.contactTitle?.trim() ?? undefined,
                    phone: d.phone?.trim() ?? undefined,
                    websiteUrl: d.websiteUrl?.trim() ?? undefined,
                    annualVolume: d.annualVolume ?? undefined,
                    physicalAddress: {
                        street: d.physicalAddress.street.trim(),
                        lga: d.physicalAddress.lga.trim(),
                        state: d.physicalAddress.state.trim(),
                        country: d.physicalAddress.country?.trim() ?? 'Nigeria',
                    },
                    onboardingStep: Math.max(profile.onboardingStep ?? 0, 1),
                },
            })
            audit({ action: 'ONBOARDING_STEP_1_COMPLETE', req, targetType: 'issuer_profile', targetId: profile.id })
            return reply.status(200).send({ success: true, message: 'Step 1 saved.' })
        })

        protectedApp.post('/onboarding/step/2', async (req, reply) => {
            const body = z.object({
                signatoryNin: z.string().regex(/^\d{11}$/, 'NIN must be exactly 11 digits'),
                signatoryWorkEmail: z.string().email(),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! } })
            if (!profile) return reply.status(404).send({ error: 'Not found', message: 'Issuer profile not found.' })
            let encryptedNin: string
            try {
                encryptedNin = encryptAES(body.data.signatoryNin)
            } catch (e: any) {
                app.log.error({ err: e }, 'NIN encryption failed')
                return reply.status(500).send({ error: 'Configuration error', message: 'Server encryption not configured. Contact support.' })
            }
            await db.issuerProfile.update({
                where: { userId: req.userId! },
                data: {
                    signatoryNin: encryptedNin,
                    signatoryWorkEmail: body.data.signatoryWorkEmail.toLowerCase().trim(),
                    onboardingStep: Math.max(profile.onboardingStep ?? 0, 2),
                },
            })
            audit({ action: 'ONBOARDING_STEP_2_COMPLETE', req, targetType: 'issuer_profile', targetId: profile.id, metadata: { ninProvided: true } })
            return reply.status(200).send({ success: true, message: 'Step 2 saved.' })
        })

        protectedApp.post('/onboarding/documents/presign', async (req, reply) => {
            const body = z.object({
                documentType: z.enum(['CAC_CERTIFICATE', 'NUC_ACCREDITATION', 'PROFESSIONAL_CHARTER', 'LETTER_OF_AUTHORITY', 'CREDENTIAL_SPECIMEN', 'LOGO']),
                filename: z.string().min(1).max(200),
                fileSize: z.number().int().min(1).max(5 * 1024 * 1024),
                mimeType: z.string().min(1).max(100),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

            const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! } })
            if (!profile) return reply.status(404).send({ error: 'Not found' })

            const { documentType, filename, mimeType } = body.data
            const storageKey = `onboarding/${profile.id}/${Date.now()}-${filename.replace(/[^a-zA-Z0-9._-]/g, '_')}`

            const bucket = env.S3_BUCKET ?? ''
            const region = env.S3_REGION ?? 'auto'
            const endpoint = env.S3_ENDPOINT ?? ''
            const accessKeyId = env.S3_ACCESS_KEY_ID ?? ''
            const secretAccessKey = env.S3_SECRET_ACCESS_KEY ?? ''

            const datetime = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z'
            const date = datetime.slice(0, 8)
            const credentialScope = `${date}/${region}/s3/aws4_request`

            const params = new URLSearchParams({
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
                'X-Amz-Date': datetime,
                'X-Amz-Expires': '300',
                'X-Amz-SignedHeaders': 'host',
            })

            const host = new URL(endpoint).host
            const canonicalUri = `/${bucket}/${storageKey}`
            const canonicalHeaders = `host:${host}\n`
            const canonicalRequest = ['PUT', canonicalUri, params.toString(), canonicalHeaders, 'host', 'UNSIGNED-PAYLOAD'].join('\n')
            const stringToSign = ['AWS4-HMAC-SHA256', datetime, credentialScope, createHash('sha256').update(canonicalRequest).digest('hex')].join('\n')

            const hmac = (k: Buffer | string, d: string) => createHmac('sha256', k).update(d).digest()
            const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, date), region), 's3'), 'aws4_request')
            const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex')
            params.set('X-Amz-Signature', signature)

            const presignedUrl = `${endpoint}/${bucket}/${storageKey}?${params.toString()}`
            return reply.status(200).send({ presignedUrl, storageKey, documentType })
        })

        protectedApp.post('/onboarding/documents/confirm', async (req, reply) => {
            const body = z.object({
                documentType: z.enum(['CAC_CERTIFICATE', 'NUC_ACCREDITATION', 'PROFESSIONAL_CHARTER', 'LETTER_OF_AUTHORITY', 'CREDENTIAL_SPECIMEN', 'LOGO']),
                storageKey: z.string().min(1),
                filename: z.string().min(1),
                mimeType: z.string().min(1),
                fileSize: z.number().int().min(1),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

            const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! } })
            if (!profile) return reply.status(404).send({ error: 'Not found' })

            if (!body.data.storageKey.startsWith(`onboarding/${profile.id}/`)) {
                return reply.status(403).send({ error: 'Forbidden', message: 'Storage key does not belong to this issuer.' })
            }

            const doc = await db.issuerDocument.upsert({
                where: { issuerId_documentType: { issuerId: profile.id, documentType: body.data.documentType } },
                create: {
                    issuerId: profile.id, documentType: body.data.documentType,
                    filename: body.data.filename, storageKey: body.data.storageKey,
                    mimeType: body.data.mimeType, fileSizeBytes: body.data.fileSize,
                    reviewStatus: 'PENDING', virusScanStatus: 'PENDING',
                },
                update: {
                    filename: body.data.filename, storageKey: body.data.storageKey,
                    mimeType: body.data.mimeType, fileSizeBytes: body.data.fileSize,
                    reviewStatus: 'PENDING', virusScanStatus: 'PENDING',
                    reviewedAt: null, reviewedById: null, reviewNote: null,
                },
            })

            audit({
                action: 'ONBOARDING_DOCUMENT_UPLOADED', req,
                targetType: 'issuer_document', targetId: doc.id,
                metadata: { documentType: body.data.documentType, filename: body.data.filename, fileSizeBytes: body.data.fileSize },
            })

            return reply.status(201).send({
                id: doc.id, documentType: doc.documentType,
                filename: doc.filename, reviewStatus: doc.reviewStatus, uploadedAt: doc.uploadedAt,
            })
        })

        protectedApp.delete('/onboarding/documents/:docId', async (req, reply) => {
            const { docId } = req.params as { docId: string }
            const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! } })
            if (!profile) return reply.status(404).send({ error: 'Not found' })
            const doc = await db.issuerDocument.findFirst({ where: { id: docId, issuerId: profile.id } })
            if (!doc) return reply.status(404).send({ error: 'Not found', message: 'Document not found.' })
            if (profile.status === 'UNDER_REVIEW' || profile.status === 'APPROVED') {
                return reply.status(409).send({ error: 'Conflict', message: 'Cannot remove documents after submission.' })
            }
            await db.issuerDocument.delete({ where: { id: docId } })
            return reply.status(204).send()
        })

        protectedApp.post('/onboarding/step/3', async (req, reply) => {
            const profile = await db.issuerProfile.findUnique({
                where: { userId: req.userId! },
                include: { documents: true },
            })
            if (!profile) return reply.status(404).send({ error: 'Not found' })
            if (profile.status === 'UNDER_REVIEW') return reply.status(409).send({ error: 'Conflict', message: 'Application is already under review.' })
            if (profile.status === 'APPROVED') return reply.status(409).send({ error: 'Conflict', message: 'Issuer is already approved.' })
            const hasCac = profile.documents.some((d: any) => d.documentType === 'CAC_CERTIFICATE')
            if (!hasCac) return reply.status(400).send({ error: 'Validation error', message: 'CAC Certificate is required before submitting for review.' })
            await db.issuerProfile.update({ where: { userId: req.userId! }, data: { status: 'UNDER_REVIEW', onboardingStep: 3 } })
            audit({ action: 'ONBOARDING_SUBMITTED_FOR_REVIEW', req, targetType: 'issuer_profile', targetId: profile.id })
            emailQueue.add('onboarding_submitted', {
                type: 'admin_notification',
                to: env.ADMIN_EMAIL ?? '',
                data: { institutionName: profile.institutionName, issuerId: profile.id, dashboardUrl: `${env.FRONTEND_URL}/pages/dashboard-admin.html` },
            }).catch((e: any) => app.log.error({ err: e }, 'Admin notification email failed'))
            return reply.status(200).send({ success: true, message: 'Application submitted for review.' })
        })

        protectedApp.get('/me/credentials', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const query = z.object({
                page: z.coerce.number().int().min(1).default(1),
                limit: z.coerce.number().int().min(1).max(100).default(25),
                status: z.enum(['ACTIVE', 'REVOKED', 'FROZEN', 'EXPIRED']).optional(),
                search: z.string().optional(),
                from: z.string().datetime().optional(),
                to: z.string().datetime().optional(),
            }).safeParse(req.query)
            if (!query.success) return reply.status(400).send({ error: 'Validation error' })
            const { page, limit, status, search, from, to } = query.data
            const where: any = {
                issuerId: req.issuerId!,
                ...(status ? { status } : {}),
                ...(search ? {
                    OR: [
                        { holderName: { contains: search, mode: 'insensitive' } },
                        { holderEmail: { contains: search, mode: 'insensitive' } },
                        { id: { contains: search } },
                    ]
                } : {}),
                ...(from || to ? { issueDate: { ...(from ? { gte: new Date(from) } : {}), ...(to ? { lte: new Date(to) } : {}) } } : {}),
            }
            const [credentials, total] = await db.$transaction([
                db.credential.findMany({
                    where,
                    select: {
                        id: true, credentialType: true, holderName: true, holderEmail: true,
                        status: true, issueDate: true, expiryDate: true, txHash: true,
                        anchoredAt: true, revokedAt: true, revocationReason: true, createdAt: true,
                        _count: { select: { verifications: true } },
                    },
                    orderBy: { createdAt: 'desc' },
                    skip: (page - 1) * limit,
                    take: limit,
                }),
                db.credential.count({ where }),
            ])
            return reply.status(200).send({ credentials, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
        })

        protectedApp.get('/me/credentials/:id', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const { id } = req.params as { id: string }
            const cred = await db.credential.findUnique({
                where: { id },
                include: {
                    verifications: {
                        take: 10, orderBy: { verifiedAt: 'desc' },
                        select: { id: true, method: true, result: true, verifiedAt: true, ipAddress: true, country: true },
                    },
                },
            })
            if (!cred || cred.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
            const serialisable = { ...cred, blockNumber: cred.blockNumber != null ? cred.blockNumber.toString() : null }
            return reply.status(200).send({ credential: serialisable })
        })

        protectedApp.get('/me/notifications', async (req, reply) => {
            try {
                const issuer = await db.issuerProfile.findUnique({ where: { userId: req.userId! }, select: { id: true } })
                if (!issuer) return reply.status(404).send({ error: 'Not found' })
                const messages = await db.onboardingMessage.findMany({
                    where: { issuerId: issuer.id, direction: 'ADMIN_TO_ISSUER' },
                    orderBy: { createdAt: 'desc' },
                    take: 30,
                })
                const notifications = messages.map(m => ({
                    id: m.id, type: 'ADMIN_NOTE', title: 'Message from VeriSure review team',
                    body: m.body, readAt: m.readAt, createdAt: m.createdAt,
                }))
                return reply.send({ notifications, unreadCount: notifications.filter(n => !n.readAt).length })
            } catch (err) {
                app.log.error({ err }, 'Get notifications error')
                return reply.status(500).send({ error: 'Server error' })
            }
        })

        protectedApp.post('/me/notifications/:id/read', async (req, reply) => {
            try {
                const { id } = req.params as { id: string }
                const issuer = await db.issuerProfile.findUnique({ where: { userId: req.userId! }, select: { id: true } })
                if (!issuer) return reply.status(404).send({ error: 'Not found' })
                await db.onboardingMessage.updateMany({ where: { id, issuerId: issuer.id }, data: { readAt: new Date() } })
                return reply.send({ ok: true })
            } catch (err) {
                app.log.error({ err }, 'Mark notification read error')
                return reply.status(500).send({ error: 'Server error' })
            }
        })

        protectedApp.get('/me/analytics', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const query = z.object({ period: z.enum(['7d', '30d', '90d', '365d']).default('30d') }).safeParse(req.query)
            if (!query.success) return reply.status(400).send({ error: 'Validation error' })
            const days = { '7d': 7, '30d': 30, '90d': 90, '365d': 365 }[query.data.period] ?? 30
            const from = new Date(Date.now() - days * 86400000)
            const issuerId = req.issuerId!
            const [
                totalIssued, totalVerifications, issuedInPeriod, verificationsInPeriod,
                byStatus, byType, revoked, topVerifiers, geo, anchorPending,
            ] = await Promise.all([
                db.credential.count({ where: { issuerId } }),
                db.verificationLog.count({ where: { credential: { issuerId } } }),
                db.credential.count({ where: { issuerId, createdAt: { gte: from } } }),
                db.verificationLog.count({ where: { credential: { issuerId }, verifiedAt: { gte: from } } }),
                db.credential.groupBy({ by: ['status'], where: { issuerId }, _count: true }),
                db.credential.groupBy({ by: ['credentialType'], where: { issuerId }, _count: true, orderBy: { _count: { credentialType: 'desc' } }, take: 10 }),
                db.credential.count({ where: { issuerId, status: 'REVOKED' } }),
                db.verificationLog.groupBy({ by: ['verifierId'], where: { credential: { issuerId }, verifierId: { not: null } }, _count: true, orderBy: { _count: { verifierId: 'desc' } }, take: 5 }),
                db.verificationLog.groupBy({ by: ['country'], where: { credential: { issuerId }, country: { not: null } }, _count: true, orderBy: { _count: { country: 'desc' } }, take: 10 }),
                db.credential.count({ where: { issuerId, txHash: null, status: { not: 'REVOKED' } } }),
            ])
            const [totalShares, sharesInPeriod, linkOpens, linkOpensInPeriod, unclaimedCredentials, geoReach] = await Promise.all([
                db.shareGrant.count({ where: { credential: { issuerId } } }),
                db.shareGrant.count({ where: { credential: { issuerId }, createdAt: { gte: from } } }),
                db.verificationLog.count({ where: { credential: { issuerId }, method: { in: ['QR_SCAN', 'SELF_VERIFY'] } } }),
                db.verificationLog.count({ where: { credential: { issuerId }, method: { in: ['QR_SCAN', 'SELF_VERIFY'] }, verifiedAt: { gte: from } } }),
                db.credential.count({ where: { issuerId, holderUserId: null, status: { not: 'REVOKED' } } }),
                db.verificationLog.groupBy({ by: ['country'], where: { credential: { issuerId }, country: { not: null } }, _count: true, orderBy: { _count: { country: 'desc' } }, take: 1 }),
            ])
            const verifierIds = topVerifiers.map(v => v.verifierId!).filter(Boolean)
            const verifierProfiles = await db.verifierProfile.findMany({ where: { id: { in: verifierIds } }, select: { id: true, organisationName: true } })
            const verifierMap = new Map(verifierProfiles.map(v => [v.id, v.organisationName]))
            const [dailyIssuances, dailyVerifications] = await Promise.all([
                buildDailySeries(issuerId, from, 'issued'),
                buildDailySeries(issuerId, from, 'verified'),
            ])
            return reply.status(200).send({
                summary: {
                    totalIssued, totalVerifications, issuedInPeriod, verificationsInPeriod,
                    revocationRate: totalIssued > 0 ? ((revoked / totalIssued) * 100).toFixed(2) + '%' : '0%',
                    pendingAnchor: anchorPending,
                },
                reach: {
                    totalShares, sharesInPeriod, linkOpens, linkOpensInPeriod,
                    countriesReached: geo.length, topCountry: geoReach[0]?.country ?? null, unclaimedCredentials,
                },
                byStatus: Object.fromEntries(byStatus.map(s => [s.status, s._count])),
                byType: byType.map(t => ({ type: t.credentialType, count: t._count })),
                topVerifiers: topVerifiers.map(v => ({ name: verifierMap.get(v.verifierId!) ?? 'Unknown', count: v._count })),
                geoDistribution: geo.map(g => ({ country: g.country ?? 'Unknown', count: g._count })),
                timeSeries: { period: query.data.period, issuances: dailyIssuances, verifications: dailyVerifications },
            })
        })

        protectedApp.post('/me/bulk-jobs', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const existingActive = await db.bulkJob.findFirst({
                where: { issuerId: req.issuerId!, type: 'issuance', status: { in: ['PENDING', 'PROCESSING'] } },
                select: { id: true, createdAt: true },
            })
            if (existingActive) {
                return reply.status(409).send({
                    error: 'Conflict',
                    message: 'You already have an active bulk issuance job. Wait for it to finish before starting another.',
                    jobId: existingActive.id,
                })
            }

            let data: Awaited<ReturnType<typeof req.file>>
            try {
                data = await req.file()
            } catch (err) {
                app.log.warn({ err }, 'bulk-jobs: multipart read failed')
                return reply.status(400).send({ error: 'Validation error', message: 'Could not read the uploaded file. Make sure it is sent as multipart/form-data under a "file" field.' })
            }
            if (!data) {
                return reply.status(400).send({ error: 'Validation error', message: 'No file uploaded. Attach a CSV file under the "file" field.' })
            }

            const filename = data.filename ?? 'upload.csv'
            const isCsv = data.mimetype === 'text/csv'
                || data.mimetype === 'application/vnd.ms-excel'
                || data.mimetype === 'application/csv'
                || filename.toLowerCase().endsWith('.csv')
            if (!isCsv) {
                return reply.status(400).send({ error: 'Validation error', message: 'Only CSV files are accepted for bulk issuance.' })
            }

            let buffer: Buffer
            try {
                buffer = await data.toBuffer()
            } catch (err) {
                app.log.warn({ err }, 'bulk-jobs: file buffering failed')
                return reply.status(413).send({ error: 'Payload too large', message: 'CSV file exceeds the upload limit.' })
            }
            if (data.file.truncated) {
                return reply.status(413).send({ error: 'Payload too large', message: 'CSV file exceeds the upload limit (5MB max).' })
            }

            let rawRows: Record<string, string>[]
            try {
                rawRows = parseCsv(buffer.toString('utf8'))
            } catch (err) {
                app.log.warn({ err }, 'bulk-jobs: csv parse failed')
                return reply.status(400).send({ error: 'Validation error', message: 'Could not parse CSV file. Check formatting and try again.' })
            }

            if (rawRows.length === 0) {
                return reply.status(400).send({ error: 'Validation error', message: 'CSV file contains no data rows.' })
            }
            if (rawRows.length > MAX_BULK_ROWS) {
                return reply.status(400).send({
                    error: 'Validation error',
                    message: `CSV contains ${rawRows.length.toLocaleString()} rows. Maximum is ${MAX_BULK_ROWS.toLocaleString()} rows per job. Split this file into multiple uploads.`,
                })
            }

            const credentials: z.infer<typeof bulkRowSchema>[] = []
            const rowErrors: { row: number; error: string }[] = []

            rawRows.forEach((raw, i) => {
                const normalised = {
                    holderName: raw['holderName']?.trim(),
                    holderEmail: raw['holderEmail']?.trim(),
                    credentialType: raw['credentialType']?.trim(),
                    field: raw['field']?.trim() || undefined,
                    notes: raw['notes']?.trim() || undefined,
                    issueDate: raw['issueDate']?.trim(),
                    expiryDate: raw['expiryDate']?.trim() || undefined,
                }
                const parsed = bulkRowSchema.safeParse(normalised)
                if (!parsed.success) {
                    rowErrors.push({ row: i + 2, error: parsed.error.issues[0]?.message ?? 'Invalid row' })
                    return
                }
                credentials.push(parsed.data)
            })

            if (credentials.length === 0) {
                return reply.status(400).send({
                    error: 'Validation error',
                    message: 'No valid rows found in CSV. Check column headers match: holderName, holderEmail, credentialType, field, issueDate, expiryDate, notes.',
                    issues: rowErrors.slice(0, 20),
                })
            }

            const job = await db.bulkJob.create({
                data: {
                    type: 'issuance',
                    issuerId: req.issuerId!,
                    filename,
                    totalRows: credentials.length,
                    status: 'PENDING',
                },
            })

            await bulkQueue.add('bulk-issuance', {
                jobId: job.id,
                type: 'issuance',
                fileKey: JSON.stringify(credentials),
                issuerId: req.issuerId!,
            })

            audit({
                action: 'BULK_IMPORT_STARTED', req, targetType: 'bulk_job', targetId: job.id,
                metadata: { rows: credentials.length, skippedRows: rowErrors.length, filename },
            })

            return reply.status(202).send({
                jobId: job.id,
                status: 'PENDING',
                rows: credentials.length,
                skippedRows: rowErrors.length,
                ...(rowErrors.length > 0 ? { rowErrorsPreview: rowErrors.slice(0, 20) } : {}),
            })
        })

        protectedApp.get('/me/bulk-jobs', async (req, reply) => {
            const jobs = await db.bulkJob.findMany({ where: { issuerId: req.issuerId!, type: 'issuance' }, orderBy: { createdAt: 'desc' }, take: 20 })
            return reply.status(200).send({ jobs })
        })

        protectedApp.get('/me/bulk-jobs/:id', async (req, reply) => {
            const { id } = req.params as { id: string }
            const job = await db.bulkJob.findUnique({ where: { id } })
            if (!job || job.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
            return reply.status(200).send({ job })
        })

        protectedApp.get('/me/team', async (req, reply) => {
            const members = await db.issuerTeamMember.findMany({ where: { issuerId: req.issuerId! }, orderBy: { invitedAt: 'desc' } })
            return reply.status(200).send({ members })
        })

        protectedApp.post('/me/team', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const body = z.object({ email: z.string().email().toLowerCase(), role: z.enum(['admin', 'issuer', 'viewer']) }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const count = await db.issuerTeamMember.count({ where: { issuerId: req.issuerId! } })
            if (count >= 20) return reply.status(429).send({ error: 'Limit exceeded', message: 'Max 20 team members' })
            const existing = await db.issuerTeamMember.findUnique({ where: { issuerId_email: { issuerId: req.issuerId!, email: body.data.email } } })
            if (existing) return reply.status(409).send({ error: 'Conflict', message: 'Already a member' })
            const token = generateSecureToken()
            const tokenHash = sha256(token)
            const member = await db.issuerTeamMember.create({
                data: { issuerId: req.issuerId!, email: body.data.email, role: body.data.role, inviteTokenHash: tokenHash, inviteExpiresAt: new Date(Date.now() + 604800000) },
            })
            const issuer = await db.issuerProfile.findUnique({ where: { id: req.issuerId! }, select: { institutionName: true } })
            await emailQueue.add('team_invite', { type: 'email_verification', to: body.data.email, data: { verifyUrl: `${env.FRONTEND_URL}/team/accept?token=${token}`, institutionName: issuer?.institutionName ?? '' } })
            return reply.status(201).send({ memberId: member.id, email: member.email, role: member.role })
        })

        protectedApp.patch('/me/team/:memberId', async (req, reply) => {
            const { memberId } = req.params as { memberId: string }
            const body = z.object({ role: z.enum(['admin', 'issuer', 'viewer']) }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error' })
            const m = await db.issuerTeamMember.findUnique({ where: { id: memberId }, select: { issuerId: true } })
            if (!m || m.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
            await db.issuerTeamMember.update({ where: { id: memberId }, data: { role: body.data.role } })
            return reply.status(200).send({ message: 'Role updated' })
        })

        protectedApp.delete('/me/team/:memberId', async (req, reply) => {
            const { memberId } = req.params as { memberId: string }
            const m = await db.issuerTeamMember.findUnique({ where: { id: memberId }, select: { issuerId: true } })
            if (!m || m.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
            await db.issuerTeamMember.delete({ where: { id: memberId } })
            return reply.status(200).send({ message: 'Member removed' })
        })

        protectedApp.get('/me/qr-template', async (req, reply) => {
            const t = await db.whitelabelPortal.findUnique({
                where: { issuerId: req.issuerId! },
                select: { id: true, displayName: true, tagline: true, primaryColor: true, logoUrl: true, customDomain: true, dnsVerified: true, isLive: true },
            })
            return reply.status(200).send({ template: t })
        })

        protectedApp.put('/me/qr-template', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const body = z.object({
                displayName: z.string().min(1).max(200),
                tagline: z.string().max(300).optional(),
                primaryColor: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional(),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const t = await db.whitelabelPortal.upsert({
                where: { issuerId: req.issuerId! },
                create: { issuerId: req.issuerId!, displayName: body.data.displayName, tagline: body.data.tagline ?? null, primaryColor: body.data.primaryColor ?? '#0047AB' },
                update: { displayName: body.data.displayName, tagline: body.data.tagline ?? null, ...(body.data.primaryColor ? { primaryColor: body.data.primaryColor } : {}) },
            })
            return reply.status(200).send({ template: t })
        })

        protectedApp.get('/me/verifications', { preHandler: requireApprovedIssuer }, async (req, reply) => {
            const query = z.object({
                page: z.coerce.number().int().min(1).default(1),
                limit: z.coerce.number().int().min(1).max(100).default(25),
            }).safeParse(req.query)
            if (!query.success) return reply.status(400).send({ error: 'Validation error' })
            const { page, limit } = query.data
            const [logs, total] = await db.$transaction([
                db.verificationLog.findMany({
                    where: { credential: { issuerId: req.issuerId! } },
                    include: {
                        credential: { select: { credentialType: true, holderName: true } },
                        verifier: { select: { organisationName: true } },
                    },
                    orderBy: { verifiedAt: 'desc' },
                    skip: (page - 1) * limit,
                    take: limit,
                }),
                db.verificationLog.count({ where: { credential: { issuerId: req.issuerId! } } }),
            ])
            return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
        })

        protectedApp.patch('/me/password', async (req, reply) => {
            const body = z.object({
                currentPassword: z.string(),
                newPassword: z.string().min(12).max(128),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const user = await db.user.findUnique({ where: { id: req.userId! }, select: { id: true, passwordHash: true } })
            if (!user) return reply.status(404).send({ error: 'Not found' })
            if (!await verifyPwd(body.data.currentPassword, user.passwordHash)) {
                return reply.status(401).send({ error: 'Unauthorized', message: 'Current password is incorrect' })
            }
            await db.user.update({ where: { id: req.userId! }, data: { passwordHash: await hashPwd(body.data.newPassword), failedLoginCount: 0 } })
            await revokeAllUserTokens(req.userId!)
            await db.userSession.updateMany({ where: { userId: req.userId!, isActive: true }, data: { isActive: false, revokedAt: new Date() } }).catch(() => { })
            audit({ action: 'USER_PASSWORD_CHANGED', req, targetType: 'user', targetId: req.userId! })
            return reply.status(200).send({ message: 'Password updated. Please log in again.' })
        })

        protectedApp.get('/me/sessions', async (req, reply) => {
            const sessions = await db.userSession.findMany({
                where: { userId: req.userId!, isActive: true },
                select: { id: true, ipAddress: true, userAgent: true, country: true, city: true, lastSeenAt: true, createdAt: true },
                orderBy: { lastSeenAt: 'desc' },
            })
            return reply.status(200).send({ sessions })
        })

        protectedApp.delete('/me/sessions/:sessionId', async (req, reply) => {
            const { sessionId } = req.params as { sessionId: string }
            const s = await db.userSession.findUnique({ where: { id: sessionId }, select: { userId: true } })
            if (!s || s.userId !== req.userId) return reply.status(404).send({ error: 'Not found' })
            await db.userSession.update({ where: { id: sessionId }, data: { isActive: false, revokedAt: new Date() } })
            audit({ action: 'TOKEN_REVOKED', req, targetType: 'user_session', targetId: sessionId })
            return reply.status(200).send({ message: 'Session revoked' })
        })

        protectedApp.delete('/me/sessions', async (req, reply) => {
            await db.userSession.updateMany({ where: { userId: req.userId!, isActive: true }, data: { isActive: false, revokedAt: new Date() } })
            await revokeAllUserTokens(req.userId!)
            audit({ action: 'TOKEN_REVOKED', req, targetType: 'user', targetId: req.userId!, metadata: { scope: 'all_sessions' } })
            return reply.status(200).send({ message: 'All sessions revoked' })
        })

        protectedApp.post('/me/2fa/setup', async (req, reply) => {
            const { generateTotpSecret, encrypt } = await import('../../lib/crypto.js')
            const secret = generateTotpSecret()
            const encrypted = encrypt(secret)
            await db.user.update({ where: { id: req.userId! }, data: { twoFactorSecret: encrypted } })
            const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
            const totpUri = `otpauth://totp/VeriSure:${user?.email}?secret=${secret}&issuer=VeriSure&algorithm=SHA1&digits=6&period=30`
            return reply.status(200).send({ secret, totpUri })
        })

        protectedApp.post('/me/2fa/confirm', async (req, reply) => {
            const body = z.object({ code: z.string().length(6) }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error' })
            const user = await db.user.findUnique({ where: { id: req.userId! }, select: { twoFactorSecret: true } })
            if (!user?.twoFactorSecret) return reply.status(400).send({ error: 'Bad request', message: 'Setup not initiated. Call /me/2fa/setup first.' })
            const { decrypt } = await import('../../lib/crypto.js')
            const { authenticator } = await import('otplib')
            const secret = decrypt(user.twoFactorSecret)
            const isValid = authenticator.verify({ token: body.data.code, secret })
            if (!isValid) return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid code. Try again.' })
            await db.user.update({ where: { id: req.userId! }, data: { twoFactorEnabled: true } })
            return reply.status(200).send({ message: '2FA enabled. You can now issue credentials.' })
        })

        protectedApp.delete('/me/2fa', async (req, reply) => {
            await db.user.update({ where: { id: req.userId! }, data: { twoFactorEnabled: false, twoFactorSecret: null } })
            return reply.status(200).send({ message: '2FA disabled.' })
        })

    })

}

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

async function buildDailySeries(issuerId: string, from: Date, type: 'issued' | 'verified') {
    if (type === 'issued') {
        const rows = await db.$queryRaw<Array<{ date: string; count: bigint }>>`
            SELECT TO_CHAR(DATE_TRUNC('day',"issueDate" AT TIME ZONE 'Africa/Lagos'),'YYYY-MM-DD') AS date,
                   COUNT(*)::bigint AS count
            FROM credentials
            WHERE "issuerId" = ${issuerId} AND "issueDate" >= ${from}
            GROUP BY DATE_TRUNC('day',"issueDate" AT TIME ZONE 'Africa/Lagos')
            ORDER BY date ASC`
        return rows.map(r => ({ date: r.date, count: Number(r.count) }))
    }
    const rows = await db.$queryRaw<Array<{ date: string; count: bigint }>>`
        SELECT TO_CHAR(DATE_TRUNC('day',vl."verifiedAt" AT TIME ZONE 'Africa/Lagos'),'YYYY-MM-DD') AS date,
               COUNT(*)::bigint AS count
        FROM verification_logs vl
        INNER JOIN credentials c ON c.id = vl."credentialId"
        WHERE c."issuerId" = ${issuerId} AND vl."verifiedAt" >= ${from}
        GROUP BY DATE_TRUNC('day',vl."verifiedAt" AT TIME ZONE 'Africa/Lagos')
        ORDER BY date ASC`
    return rows.map(r => ({ date: r.date, count: Number(r.count) }))
}

function encryptAES(plaintext: string): string {
    const key = Buffer.from(env.ENCRYPTION_KEY, 'hex')
    if (key.length !== 32) throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex chars)')
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return iv.toString('hex') + tag.toString('hex') + encrypted.toString('hex')
}