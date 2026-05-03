import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../../lib/db.js'
import { generateSecureToken, sha256 } from '../../lib/crypto.js'
import { anchorQueue, emailQueue, bulkQueue } from '../../lib/queue.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireIssuer, requireApprovedIssuer } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { env } from '../../config/env.js'
import { generateCredentialId, hashCredential } from '../../lib/crypto.js'

export default async function issuerRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireIssuer)

    // ── PROFILE ───────────────────────────────────────────────────
    app.get('/me', async (req, reply) => {
        const profile = await db.issuerProfile.findUnique({ where: { userId: req.userId! }, include: { _count: { select: { credentials: true, teamMembers: true } }, whitelabelPortal: { select: { id: true, customDomain: true, displayName: true, isLive: true, dnsVerified: true } } } })
        if (!profile) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ profile })
    })

    app.patch('/me', async (req, reply) => {
        const body = z.object({ institutionName: z.string().max(200).optional(), institutionType: z.string().optional(), registrationNumber: z.string().optional(), phone: z.string().optional(), websiteUrl: z.string().url().optional(), contactFirstName: z.string().optional(), contactLastName: z.string().optional(), contactTitle: z.string().optional() }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
        const profile = await db.issuerProfile.update({ where: { userId: req.userId! }, data: body.data, select: { id: true, institutionName: true, institutionType: true, status: true } })
        return reply.status(200).send({ profile })
    })

    // ── CREDENTIALS ───────────────────────────────────────────────
    app.get('/me/credentials', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const query = z.object({ page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(100).default(25), status: z.enum(['ACTIVE', 'REVOKED', 'FROZEN', 'EXPIRED']).optional(), search: z.string().optional(), from: z.string().datetime().optional(), to: z.string().datetime().optional() }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit, status, search, from, to } = query.data
        const where: any = { issuerId: req.issuerId!, ...(status ? { status } : {}), ...(search ? { OR: [{ holderName: { contains: search, mode: 'insensitive' } }, { holderEmail: { contains: search, mode: 'insensitive' } }, { id: { contains: search } }] } : {}), ...(from || to ? { issueDate: { ...(from ? { gte: new Date(from) } : {}), ...(to ? { lte: new Date(to) } : {}) } } : {}) }

        const [credentials, total] = await db.$transaction([
            db.credential.findMany({ where, select: { id: true, credentialType: true, holderName: true, holderEmail: true, status: true, issueDate: true, expiryDate: true, txHash: true, anchoredAt: true, revokedAt: true, revocationReason: true, createdAt: true, _count: { select: { verifications: true } } }, orderBy: { createdAt: 'desc' }, skip: (page - 1) * limit, take: limit }),
            db.credential.count({ where }),
        ])

        return reply.status(200).send({ credentials, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    app.get('/me/credentials/:id', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const { id } = req.params as { id: string }
        const cred = await db.credential.findUnique({ where: { id }, include: { verifications: { take: 10, orderBy: { verifiedAt: 'desc' }, select: { id: true, method: true, result: true, verifiedAt: true, ipAddress: true, country: true } } } })
        if (!cred || cred.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ credential: cred })
    })

    // ── ANALYTICS ─────────────────────────────────────────────────
    app.get('/me/analytics', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const query = z.object({ period: z.enum(['7d', '30d', '90d', '365d']).default('30d') }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const days = { '7d': 7, '30d': 30, '90d': 90, '365d': 365 }[query.data.period] ?? 30
        const from = new Date(Date.now() - days * 86400000)
        const issuerId = req.issuerId!

        const [totalIssued, totalVerifications, issuedInPeriod, verificationsInPeriod, byStatus, byType, revoked, topVerifiers, geo, anchorPending] = await Promise.all([
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

        const verifierIds = topVerifiers.map(v => v.verifierId!).filter(Boolean)
        const verifierProfiles = await db.verifierProfile.findMany({ where: { id: { in: verifierIds } }, select: { id: true, organisationName: true } })
        const verifierMap = new Map(verifierProfiles.map(v => [v.id, v.organisationName]))

        const [dailyIssuances, dailyVerifications] = await Promise.all([buildDailySeries(issuerId, from, 'issued'), buildDailySeries(issuerId, from, 'verified')])

        return reply.status(200).send({
            summary: { totalIssued, totalVerifications, issuedInPeriod, verificationsInPeriod, revocationRate: totalIssued > 0 ? ((revoked / totalIssued) * 100).toFixed(2) + '%' : '0%', pendingAnchor: anchorPending },
            byStatus: Object.fromEntries(byStatus.map(s => [s.status, s._count])),
            byType: byType.map(t => ({ type: t.credentialType, count: t._count })),
            topVerifiers: topVerifiers.map(v => ({ name: verifierMap.get(v.verifierId!) ?? 'Unknown', count: v._count })),
            geoDistribution: geo.map(g => ({ country: g.country ?? 'Unknown', count: g._count })),
            timeSeries: { period: query.data.period, issuances: dailyIssuances, verifications: dailyVerifications },
        })
    })

    // ── BULK ISSUANCE ─────────────────────────────────────────────
    app.post('/me/bulk-jobs', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const body = z.object({ credentials: z.array(z.object({ holderName: z.string().min(1), holderEmail: z.string().email().toLowerCase(), credentialType: z.string().min(1), field: z.string().optional(), notes: z.string().optional(), issueDate: z.string(), expiryDate: z.string().optional() })).min(1).max(10000), filename: z.string().optional() }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const job = await db.bulkJob.create({ data: { type: 'issuance', issuerId: req.issuerId!, filename: body.data.filename ?? `bulk_${Date.now()}.json`, totalRows: body.data.credentials.length, status: 'PENDING' } })
        await bulkQueue.add('bulk-issuance', { jobId: job.id, type: 'issuance', fileKey: JSON.stringify(body.data.credentials), issuerId: req.issuerId! })

        audit({ action: 'BULK_IMPORT_STARTED', req, targetType: 'bulk_job', targetId: job.id, metadata: { rows: body.data.credentials.length } })

        return reply.status(202).send({ jobId: job.id, status: 'PENDING', rows: body.data.credentials.length })
    })

    app.get('/me/bulk-jobs', async (req, reply) => {
        const jobs = await db.bulkJob.findMany({ where: { issuerId: req.issuerId!, type: 'issuance' }, orderBy: { createdAt: 'desc' }, take: 20 })
        return reply.status(200).send({ jobs })
    })

    app.get('/me/bulk-jobs/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const job = await db.bulkJob.findUnique({ where: { id } })
        if (!job || job.issuerId !== req.issuerId) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ job })
    })

    // ── TEAM ──────────────────────────────────────────────────────
    app.get('/me/team', async (req, reply) => {
        const members = await db.issuerTeamMember.findMany({ where: { issuerId: req.issuerId! }, orderBy: { invitedAt: 'desc' } })
        return reply.status(200).send({ members })
    })

    app.post('/me/team', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const body = z.object({ email: z.string().email().toLowerCase(), role: z.enum(['admin', 'issuer', 'viewer']) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const count = await db.issuerTeamMember.count({ where: { issuerId: req.issuerId! } })
        if (count >= 20) return reply.status(429).send({ error: 'Limit exceeded', message: 'Max 20 team members' })

        const existing = await db.issuerTeamMember.findUnique({ where: { issuerId_email: { issuerId: req.issuerId!, email: body.data.email } } })
        if (existing) return reply.status(409).send({ error: 'Conflict', message: 'Already a member' })

        const token = generateSecureToken()
        const tokenHash = sha256(token)

        const member = await db.issuerTeamMember.create({ data: { issuerId: req.issuerId!, email: body.data.email, role: body.data.role, inviteTokenHash: tokenHash, inviteExpiresAt: new Date(Date.now() + 604800000) } })

        const issuer = await db.issuerProfile.findUnique({ where: { id: req.issuerId! }, select: { institutionName: true } })
        await emailQueue.add('team_invite', { type: 'email_verification', to: body.data.email, data: { verifyUrl: `${env.FRONTEND_URL}/team/accept?token=${token}`, institutionName: issuer?.institutionName ?? '' } })

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

    // ── QR TEMPLATE ───────────────────────────────────────────────
    app.get('/me/qr-template', async (req, reply) => {
        const t = await db.whitelabelPortal.findUnique({ where: { issuerId: req.issuerId! }, select: { id: true, displayName: true, tagline: true, primaryColor: true, logoUrl: true, customDomain: true, dnsVerified: true, isLive: true } })
        return reply.status(200).send({ template: t })
    })

    app.put('/me/qr-template', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const body = z.object({ displayName: z.string().min(1).max(200), tagline: z.string().max(300).optional(), primaryColor: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional() }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const t = await db.whitelabelPortal.upsert({ where: { issuerId: req.issuerId! }, create: { issuerId: req.issuerId!, displayName: body.data.displayName, tagline: body.data.tagline ?? null, primaryColor: body.data.primaryColor ?? '#0047AB' }, update: { displayName: body.data.displayName, tagline: body.data.tagline ?? null, ...(body.data.primaryColor ? { primaryColor: body.data.primaryColor } : {}) } })
        return reply.status(200).send({ template: t })
    })

    // ── VERIFICATION HISTORY ──────────────────────────────────────
    app.get('/me/verifications', { preHandler: requireApprovedIssuer }, async (req, reply) => {
        const query = z.object({ page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(100).default(25) }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit } = query.data
        const [logs, total] = await db.$transaction([
            db.verificationLog.findMany({ where: { credential: { issuerId: req.issuerId! } }, include: { credential: { select: { credentialType: true, holderName: true } } }, orderBy: { verifiedAt: 'desc' }, skip: (page - 1) * limit, take: limit }),
            db.verificationLog.count({ where: { credential: { issuerId: req.issuerId! } } }),
        ])

        return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })
}

// ── HELPERS ───────────────────────────────────────────────────
async function buildDailySeries(issuerId: string, from: Date, type: 'issued' | 'verified') {
    if (type === 'issued') {
        const rows = await db.$queryRaw<Array<{ date: string; count: bigint }>>`
      SELECT TO_CHAR(DATE_TRUNC('day',"issueDate" AT TIME ZONE 'Africa/Lagos'),'YYYY-MM-DD') AS date, COUNT(*)::bigint AS count
      FROM credentials WHERE "issuerId" = ${issuerId} AND "issueDate" >= ${from}
      GROUP BY DATE_TRUNC('day',"issueDate" AT TIME ZONE 'Africa/Lagos') ORDER BY date ASC`
        return rows.map(r => ({ date: r.date, count: Number(r.count) }))
    }
    const rows = await db.$queryRaw<Array<{ date: string; count: bigint }>>`
    SELECT TO_CHAR(DATE_TRUNC('day',vl."verifiedAt" AT TIME ZONE 'Africa/Lagos'),'YYYY-MM-DD') AS date, COUNT(*)::bigint AS count
    FROM verification_logs vl INNER JOIN credentials c ON c.id = vl."credentialId"
    WHERE c."issuerId" = ${issuerId} AND vl."verifiedAt" >= ${from}
    GROUP BY DATE_TRUNC('day',vl."verifiedAt" AT TIME ZONE 'Africa/Lagos') ORDER BY date ASC`
    return rows.map(r => ({ date: r.date, count: Number(r.count) }))
}