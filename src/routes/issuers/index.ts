import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../../lib/db.js'
import { redis, keys } from '../../lib/redis.js'
import { generateSecureToken, sha256, generateCredentialId, hashCredential } from '../../lib/crypto.js'
import { anchorQueue, emailQueue, bulkQueue } from '../../lib/queue.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireIssuer, requireApprovedIssuer } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { env } from '../../config/env.js'
import { createCipheriv, randomBytes } from 'node:crypto'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'

export default async function issuerRoutes(app: FastifyInstance) {

    app.get(
        '/public',
        {
            schema: {
                querystring: z.object({
                    page: z.coerce.number().int().positive().default(1),
                    limit: z.coerce.number().int().min(1).max(100).default(48),
                    search: z.string().max(120).optional(),
                    type: z.string().max(80).optional(),
                }),
            },
        },
        async (request, reply) => {
            const { page, limit, search, type } = request.query as {
                page: number;
                limit: number;
                search?: string;
                type?: string;
            };

            const skip = (page - 1) * limit;

            const where: any = { status: 'APPROVED' };

            if (search?.trim()) {
                where.institutionName = {
                    contains: search.trim(),
                    mode: 'insensitive',
                };
            }

            if (type?.trim()) {
                where.institutionType = type.trim();
            }

            const [issuers, total] = await Promise.all([
                db.issuerProfile.findMany({
                    where,
                    skip,
                    take: limit,
                    orderBy: { approvedAt: 'desc' },
                    select: {
                        id: true,
                        institutionName: true,
                        institutionType: true,
                        websiteUrl: true,
                        logoUrl: true,
                        approvedAt: true,
                        _count: {
                            select: { credentials: true },
                        },
                    },
                }),
                db.issuerProfile.count({ where }),
            ]);

            return reply.send({
                issuers,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.ceil(total / limit),
                },
            });
        }
    );

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireIssuer)

    // ── PROFILE ──────────────────────────────────────────────────────────────

    app.get('/me', async (req, reply) => {
        const profile = await db.issuerProfile.findUnique({
            where: { userId: req.userId! },
            include: {
                _count: { select: { credentials: true, teamMembers: true } },
                whitelabelPortal: {
                    select: { id: true, customDomain: true, displayName: true, isLive: true, dnsVerified: true },
                },
                documents: {
                    select: {
                        id: true,
                        documentType: true,
                        filename: true,
                        reviewStatus: true,
                        reviewNote: true,
                        uploadedAt: true,
                    },
                    orderBy: { uploadedAt: 'asc' },
                },
                messages: {
                    where: { direction: 'ADMIN_TO_ISSUER' },
                    select: {
                        id: true,
                        direction: true,
                        body: true,
                        readAt: true,
                        createdAt: true,
                    },
                    orderBy: { createdAt: 'asc' },
                },
            },
        })
        if (!profile) return reply.status(404).send({ error: 'Not found' })

        const safeProfile = {
            ...profile,
            signatoryNin: profile.signatoryNin ? 'XXX-XXXX-XXXXX' : null,
        }

        return reply.status(200).send({ profile: safeProfile })
    })

    app.patch('/me', async (req, reply) => {
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

    // ── ONBOARDING — STEP 1: Institution profile ──────────────────────────────

    app.post('/onboarding/step/1', async (req, reply) => {
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

        audit({
            action: 'ONBOARDING_STEP_1_COMPLETE',
            req,
            targetType: 'issuer_profile',
            targetId: profile.id,
        })

        return reply.status(200).send({ success: true, message: 'Step 1 saved.' })
    })

    // ── ONBOARDING — STEP 2: Signatory + NIN ─────────────────────────────────

    app.post('/onboarding/step/2', async (req, reply) => {
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
            app.log.error({ err: e }, 'NIN encryption failed — ENCRYPTION_KEY not configured')
            return reply.status(500).send({
                error: 'Configuration error',
                message: 'Server encryption not configured. Contact support.',
            })
        }

        await db.issuerProfile.update({
            where: { userId: req.userId! },
            data: {
                signatoryNin: encryptedNin,
                signatoryWorkEmail: body.data.signatoryWorkEmail.toLowerCase().trim(),
                onboardingStep: Math.max(profile.onboardingStep ?? 0, 2),
            },
        })

        audit({
            action: 'ONBOARDING_STEP_2_COMPLETE',
            req,
            targetType: 'issuer_profile',
            targetId: profile.id,
            metadata: { ninProvided: true },
        })

        return reply.status(200).send({ success: true, message: 'Step 2 saved.' })
    })

    // ── ONBOARDING — DOCUMENT UPLOAD ─────────────────────────────────────────

    app.post('/onboarding/documents', async (req, reply) => {
        const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! } })
        if (!profile) return reply.status(404).send({ error: 'Not found', message: 'Issuer profile not found.' })

        const data = await (req as any).file()
        if (!data) return reply.status(400).send({ error: 'Validation error', message: 'No file received.' })

        const docType = data.fields?.documentType?.value ?? data.fields?.documentType
        const validDocTypes = [
            'CAC_CERTIFICATE', 'NUC_ACCREDITATION', 'PROFESSIONAL_CHARTER',
            'LETTER_OF_AUTHORITY', 'CREDENTIAL_SPECIMEN', 'LOGO',
        ]
        if (!docType || !validDocTypes.includes(docType)) {
            return reply.status(400).send({
                error: 'Validation error',
                message: `documentType must be one of: ${validDocTypes.join(', ')}`,
            })
        }

        const allowedMimes = ['application/pdf', 'image/jpeg', 'image/png', 'image/svg+xml']
        if (!allowedMimes.includes(data.mimetype ?? '')) {
            return reply.status(400).send({
                error: 'Validation error',
                message: 'Only PDF, JPG, PNG, and SVG files are accepted.',
            })
        }

        const MAX_SIZE = 5 * 1024 * 1024
        const chunks: Buffer[] = []
        let totalSize = 0
        for await (const chunk of data.file) {
            totalSize += chunk.length
            if (totalSize > MAX_SIZE) {
                return reply.status(413).send({ error: 'File too large', message: 'Maximum file size is 5 MB.' })
            }
            chunks.push(chunk)
        }

        const fileBuffer = Buffer.concat(chunks)
        const filename = data.filename ?? `document-${Date.now()}`

        let storageKey: string
        try {
            storageKey = await uploadToS3(fileBuffer, filename, data.mimetype, profile.id)
        } catch (e: any) {
            app.log.error({ err: e }, 'Document upload to S3 failed')
            return reply.status(500).send({ error: 'Storage error', message: 'Upload failed. Please try again.' })
        }

        const doc = await db.issuerDocument.upsert({
            where: { issuerId_documentType: { issuerId: profile.id, documentType: docType as any } },
            create: {
                issuerId: profile.id,
                documentType: docType as any,
                filename,
                storageKey,
                mimeType: data.mimetype,
                fileSizeBytes: totalSize,
                reviewStatus: 'PENDING',
                virusScanStatus: 'PENDING',
            },
            update: {
                filename,
                storageKey,
                mimeType: data.mimetype,
                fileSizeBytes: totalSize,
                reviewStatus: 'PENDING',
                virusScanStatus: 'PENDING',
                reviewedAt: null,
                reviewedById: null,
                reviewNote: null,
            },
        })

        audit({
            action: 'ONBOARDING_DOCUMENT_UPLOADED',
            req,
            targetType: 'issuer_document',
            targetId: doc.id,
            metadata: { documentType: docType, filename, fileSizeBytes: totalSize },
        })

        return reply.status(201).send({
            id: doc.id,
            documentType: doc.documentType,
            filename: doc.filename,
            reviewStatus: doc.reviewStatus,
            uploadedAt: doc.uploadedAt,
        })
    })

    app.delete('/onboarding/documents/:docId', async (req, reply) => {
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

    // ── ONBOARDING — STEP 3: Submit for review ────────────────────────────────

    app.post('/onboarding/step/3', async (req, reply) => {
        const profile = await db.issuerProfile.findUnique({
            where: { userId: req.userId! },
            include: { documents: true },
        })
        if (!profile) return reply.status(404).send({ error: 'Not found' })

        if (profile.status === 'UNDER_REVIEW') {
            return reply.status(409).send({ error: 'Conflict', message: 'Application is already under review.' })
        }
        if (profile.status === 'APPROVED') {
            return reply.status(409).send({ error: 'Conflict', message: 'Issuer is already approved.' })
        }

        const hasCac = profile.documents.some((d: any) => d.documentType === 'CAC_CERTIFICATE')
        if (!hasCac) {
            return reply.status(400).send({
                error: 'Validation error',
                message: 'CAC Certificate is required before submitting for review.',
            })
        }

        await db.issuerProfile.update({
            where: { userId: req.userId! },
            data: { status: 'UNDER_REVIEW', onboardingStep: 3 },
        })

        audit({
            action: 'ONBOARDING_SUBMITTED_FOR_REVIEW',
            req,
            targetType: 'issuer_profile',
            targetId: profile.id,
        })

        emailQueue.add('onboarding_submitted', {
            type: 'admin_notification',
            to: env.ADMIN_EMAIL ?? process.env['ADMIN_EMAIL'] ?? '',
            data: {
                institutionName: profile.institutionName,
                issuerId: profile.id,
                dashboardUrl: `${env.FRONTEND_URL}/pages/dashboard-admin.html`,
            },
        }).catch((e: any) => app.log.error({ err: e }, 'Admin notification email failed'))

        return reply.status(200).send({ success: true, message: 'Application submitted for review.' })
    })

    // ── CREDENTIALS ───────────────────────────────────────────────────────────

    app.get('/me/credentials', { preHandler: requireApprovedIssuer }, async (req, reply) => {
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
            ...(from || to ? {
                issueDate: {
                    ...(from ? { gte: new Date(from) } : {}),
                    ...(to ? { lte: new Date(to) } : {}),
                }
            } : {}),
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

    app.get('/me/credentials/:id', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const { id } = req.params as { id: string }
        const cred = await db.credential.findUnique({
            where: { id },
            include: {
                verifications: {
                    take: 10,
                    orderBy: { verifiedAt: 'desc' },
                    select: { id: true, method: true, result: true, verifiedAt: true, ipAddress: true, country: true },
                },
            },
        })
        if (!cred || cred.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ credential: cred })
    })

    // ── ANALYTICS ─────────────────────────────────────────────────────────────

    app.get('/me/analytics', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const query = z.object({
            period: z.enum(['7d', '30d', '90d', '365d']).default('30d'),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const days = { '7d': 7, '30d': 30, '90d': 90, '365d': 365 }[query.data.period] ?? 30
        const from = new Date(Date.now() - days * 86400000)
        const issuerId = req.issuerId!

        // ── CORE METRICS (unchanged) ──────────────────────────────────────────
        const [
            totalIssued,
            totalVerifications,
            issuedInPeriod,
            verificationsInPeriod,
            byStatus,
            byType,
            revoked,
            topVerifiers,
            geo,
            anchorPending,
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

        // ── REACH METRICS — holder-driven signals ─────────────────────────────
        // These measure how far credentials travel independent of formal verifier
        // registrations. An issuer with 0 registered verifiers can still have
        // thousands of link views from holders sharing directly with employers.
        const [
            totalShares,
            sharesInPeriod,
            linkOpens,
            linkOpensInPeriod,
            unclaimedCredentials,
            geoReach,
        ] = await Promise.all([
            // Total share grants created for credentials issued by this institution
            db.shareGrant.count({
                where: { credential: { issuerId } },
            }),
            // Share grants created within the current period
            db.shareGrant.count({
                where: { credential: { issuerId }, createdAt: { gte: from } },
            }),
            // Verification link views: QR scans + share grant accesses
            // These represent employer/third-party views without a registered account
            db.verificationLog.count({
                where: {
                    credential: { issuerId },
                    method: { in: ['QR_SCAN', 'SELF_VERIFY'] },
                },
            }),
            // Link opens within the current period
            db.verificationLog.count({
                where: {
                    credential: { issuerId },
                    method: { in: ['QR_SCAN', 'SELF_VERIFY'] },
                    verifiedAt: { gte: from },
                },
            }),
            // Credentials that haven't been claimed by a holder yet
            // (issued to an email with no VeriSure account)
            db.credential.count({
                where: { issuerId, holderUserId: null, status: { not: 'REVOKED' } },
            }),
            // Geographic reach — distinct countries across ALL verification methods
            // (not just registered verifiers)
            db.verificationLog.groupBy({
                by: ['country'],
                where: { credential: { issuerId }, country: { not: null } },
                _count: true,
                orderBy: { _count: { country: 'desc' } },
                take: 1,
            }),
        ])

        const countriesReached = geo.length  // already queried above as top 10
        const topCountry = geoReach[0]?.country ?? null

        // ── VERIFIER NAME RESOLUTION (unchanged) ─────────────────────────────
        const verifierIds = topVerifiers.map(v => v.verifierId!).filter(Boolean)
        const verifierProfiles = await db.verifierProfile.findMany({
            where: { id: { in: verifierIds } },
            select: { id: true, organisationName: true },
        })
        const verifierMap = new Map(verifierProfiles.map(v => [v.id, v.organisationName]))

        const [dailyIssuances, dailyVerifications] = await Promise.all([
            buildDailySeries(issuerId, from, 'issued'),
            buildDailySeries(issuerId, from, 'verified'),
        ])

        return reply.status(200).send({
            summary: {
                totalIssued,
                totalVerifications,
                issuedInPeriod,
                verificationsInPeriod,
                revocationRate: totalIssued > 0 ? ((revoked / totalIssued) * 100).toFixed(2) + '%' : '0%',
                pendingAnchor: anchorPending,
            },
            // Holder-driven reach metrics — visible in the issuer analytics dashboard.
            // These compound independently of the verifier network size.
            reach: {
                totalShares,
                sharesInPeriod,
                linkOpens,
                linkOpensInPeriod,
                countriesReached,
                topCountry,
                unclaimedCredentials,
            },
            byStatus: Object.fromEntries(byStatus.map(s => [s.status, s._count])),
            byType: byType.map(t => ({ type: t.credentialType, count: t._count })),
            topVerifiers: topVerifiers.map(v => ({ name: verifierMap.get(v.verifierId!) ?? 'Unknown', count: v._count })),
            geoDistribution: geo.map(g => ({ country: g.country ?? 'Unknown', count: g._count })),
            timeSeries: { period: query.data.period, issuances: dailyIssuances, verifications: dailyVerifications },
        })
    })

    // ── BULK ISSUANCE ─────────────────────────────────────────────────────────

    app.post('/me/bulk-jobs', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const body = z.object({
            credentials: z.array(z.object({
                holderName: z.string().min(1),
                holderEmail: z.string().email().toLowerCase(),
                credentialType: z.string().min(1),
                field: z.string().optional(),
                notes: z.string().optional(),
                issueDate: z.string(),
                expiryDate: z.string().optional(),
            })).min(1).max(10000),
            filename: z.string().optional(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const job = await db.bulkJob.create({
            data: {
                type: 'issuance',
                issuerId: req.issuerId!,
                filename: body.data.filename ?? `bulk_${Date.now()}.json`,
                totalRows: body.data.credentials.length,
                status: 'PENDING',
            },
        })
        await bulkQueue.add('bulk-issuance', {
            jobId: job.id,
            type: 'issuance',
            fileKey: JSON.stringify(body.data.credentials),
            issuerId: req.issuerId!,
        })

        audit({ action: 'BULK_IMPORT_STARTED', req, targetType: 'bulk_job', targetId: job.id, metadata: { rows: body.data.credentials.length } })

        return reply.status(202).send({ jobId: job.id, status: 'PENDING', rows: body.data.credentials.length })
    })

    app.get('/me/bulk-jobs', async (req, reply) => {
        const jobs = await db.bulkJob.findMany({
            where: { issuerId: req.issuerId!, type: 'issuance' },
            orderBy: { createdAt: 'desc' },
            take: 20,
        })
        return reply.status(200).send({ jobs })
    })

    app.get('/me/bulk-jobs/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const job = await db.bulkJob.findUnique({ where: { id } })
        if (!job || job.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ job })
    })

    // ── TEAM ──────────────────────────────────────────────────────────────────

    app.get('/me/team', async (req, reply) => {
        const members = await db.issuerTeamMember.findMany({
            where: { issuerId: req.issuerId! },
            orderBy: { invitedAt: 'desc' },
        })
        return reply.status(200).send({ members })
    })

    app.post('/me/team', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const body = z.object({
            email: z.string().email().toLowerCase(),
            role: z.enum(['admin', 'issuer', 'viewer']),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const count = await db.issuerTeamMember.count({ where: { issuerId: req.issuerId! } })
        if (count >= 20) return reply.status(429).send({ error: 'Limit exceeded', message: 'Max 20 team members' })

        const existing = await db.issuerTeamMember.findUnique({
            where: { issuerId_email: { issuerId: req.issuerId!, email: body.data.email } },
        })
        if (existing) return reply.status(409).send({ error: 'Conflict', message: 'Already a member' })

        const token = generateSecureToken()
        const tokenHash = sha256(token)
        const member = await db.issuerTeamMember.create({
            data: {
                issuerId: req.issuerId!,
                email: body.data.email,
                role: body.data.role,
                inviteTokenHash: tokenHash,
                inviteExpiresAt: new Date(Date.now() + 604800000),
            },
        })

        const issuer = await db.issuerProfile.findUnique({
            where: { id: req.issuerId! },
            select: { institutionName: true },
        })
        await emailQueue.add('team_invite', {
            type: 'email_verification',
            to: body.data.email,
            data: { verifyUrl: `${env.FRONTEND_URL}/team/accept?token=${token}`, institutionName: issuer?.institutionName ?? '' },
        })

        return reply.status(201).send({ memberId: member.id, email: member.email, role: member.role })
    })

    app.patch('/me/team/:memberId', async (req, reply) => {
        const { memberId } = req.params as { memberId: string }
        const body = z.object({ role: z.enum(['admin', 'issuer', 'viewer']) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error' })

        const m = await db.issuerTeamMember.findUnique({ where: { id: memberId }, select: { issuerId: true } })
        if (!m || m.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })

        await db.issuerTeamMember.update({ where: { id: memberId }, data: { role: body.data.role } })
        return reply.status(200).send({ message: 'Role updated' })
    })

    app.delete('/me/team/:memberId', async (req, reply) => {
        const { memberId } = req.params as { memberId: string }
        const m = await db.issuerTeamMember.findUnique({ where: { id: memberId }, select: { issuerId: true } })
        if (!m || m.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
        await db.issuerTeamMember.delete({ where: { id: memberId } })
        return reply.status(200).send({ message: 'Member removed' })
    })

    // ── QR TEMPLATE ───────────────────────────────────────────────────────────

    app.get('/me/qr-template', async (req, reply) => {
        const t = await db.whitelabelPortal.findUnique({
            where: { issuerId: req.issuerId! },
            select: { id: true, displayName: true, tagline: true, primaryColor: true, logoUrl: true, customDomain: true, dnsVerified: true, isLive: true },
        })
        return reply.status(200).send({ template: t })
    })

    app.put('/me/qr-template', { preHandler: requireApprovedIssuer }, async (req, reply) => {
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

    // ── VERIFICATION HISTORY ──────────────────────────────────────────────────

    app.get('/me/verifications', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const query = z.object({
            page: z.coerce.number().int().min(1).default(1),
            limit: z.coerce.number().int().min(1).max(100).default(25),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit } = query.data
        const [logs, total] = await db.$transaction([
            db.verificationLog.findMany({
                where: { credential: { issuerId: req.issuerId! } },
                include: { credential: { select: { credentialType: true, holderName: true } } },
                orderBy: { verifiedAt: 'desc' },
                skip: (page - 1) * limit,
                take: limit,
            }),
            db.verificationLog.count({ where: { credential: { issuerId: req.issuerId! } } }),
        ])

        return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

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
    const key = Buffer.from(process.env['ENCRYPTION_KEY'] ?? '', 'hex')
    if (key.length !== 32) throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex chars)')
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return iv.toString('hex') + tag.toString('hex') + encrypted.toString('hex')
}

async function uploadToS3(fileBuffer: Buffer, filename: string, mimeType: string, issuerId: string): Promise<string> {
    const s3 = new S3Client({ region: process.env['AWS_REGION'] ?? 'us-east-1' })
    const key = `onboarding/${issuerId}/${Date.now()}-${filename.replace(/[^a-zA-Z0-9._-]/g, '_')}`
    await s3.send(new PutObjectCommand({
        Bucket: process.env['S3_BUCKET'],
        Key: key,
        Body: fileBuffer,
        ContentType: mimeType,
        ServerSideEncryption: 'AES256',
    }))
    return key
}