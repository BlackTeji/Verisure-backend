import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { scrypt, randomBytes } from 'crypto'
import { promisify } from 'util'
import { db } from '../../lib/db.js'
import { generateSecureToken, sha256, encrypt, generateTotpSecret } from '../../lib/crypto.js'
import { authenticate } from '../../hooks/authenticate.js'
import { requireHolder } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { revokeAllUserTokens } from '../../lib/jwt.js'
import { env } from '../../config/env.js'

const scryptAsync = promisify(scrypt)

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

export default async function holderRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireHolder)

    // ── WALLET ────────────────────────────────────────────────────
    app.get('/me/credentials', async (req, reply) => {
        const query = z.object({ status: z.enum(['ACTIVE', 'REVOKED', 'FROZEN', 'EXPIRED']).optional(), sort: z.enum(['newest', 'oldest', 'issuer']).default('newest') }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })

        const where: any = { OR: [{ holderUserId: req.userId }, { holderEmail: user?.email }], ...(query.data.status ? { status: query.data.status } : {}) }
        const orderBy = query.data.sort === 'oldest' ? { createdAt: 'asc' as const } : query.data.sort === 'issuer' ? { issuer: { institutionName: 'asc' as const } } : { createdAt: 'desc' as const }

        const credentials = await db.credential.findMany({ where, include: { issuer: { select: { id: true, institutionName: true, institutionType: true, status: true } }, _count: { select: { verifications: true } } }, orderBy })

        const now = new Date()
        const enriched = credentials.map(c => ({ ...c, status: c.expiryDate && c.expiryDate < now && c.status === 'ACTIVE' ? 'EXPIRED' : c.status, expiresInDays: c.expiryDate ? Math.ceil((c.expiryDate.getTime() - now.getTime()) / 86400000) : null }))

        return reply.status(200).send({ credentials: enriched })
    })

    app.get('/me/credentials/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        const cred = await db.credential.findUnique({ where: { id }, include: { issuer: { select: { id: true, institutionName: true, institutionType: true, status: true } } } })

        if (!cred) return reply.status(404).send({ error: 'Not found' })

        const owns = cred.holderUserId === req.userId || cred.holderEmail === user?.email
        if (!owns) return reply.status(403).send({ error: 'Forbidden' })

        if (!cred.holderUserId && cred.holderEmail === user?.email) {
            await db.credential.update({ where: { id }, data: { holderUserId: req.userId } })
        }

        return reply.status(200).send({ credential: cred })
    })

    // ── SHARES ────────────────────────────────────────────────────
    app.get('/me/shares', async (req, reply) => {
        const profile = await db.holderProfile.findUnique({ where: { userId: req.userId! }, select: { id: true } })
        if (!profile) return reply.status(404).send({ error: 'Profile not found' })

        const grants = await db.shareGrant.findMany({ where: { holderId: profile.id }, include: { credential: { select: { id: true, credentialType: true, issuer: { select: { institutionName: true } } } } }, orderBy: { createdAt: 'desc' } })

        const now = new Date()
        const enriched = grants.map(({ tokenHash: _th, ...g }) => ({ ...g, isExpired: g.expiresAt ? g.expiresAt < now : false, isActive: !g.isRevoked && (!g.expiresAt || g.expiresAt >= now) }))

        return reply.status(200).send({ grants: enriched })
    })

    app.post('/me/shares', async (req, reply) => {
        const body = z.object({ credentialId: z.string(), recipientEmail: z.string().email().toLowerCase().optional(), expiresIn: z.enum(['none', '24h', '7d', '30d', '90d']).default('none') }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        const profile = await db.holderProfile.findUnique({ where: { userId: req.userId! } })
        if (!profile) return reply.status(404).send({ error: 'Profile not found' })

        const cred = await db.credential.findUnique({ where: { id: body.data.credentialId }, select: { id: true, holderUserId: true, holderEmail: true } })
        if (!cred) return reply.status(404).send({ error: 'Credential not found' })

        if (cred.holderUserId !== req.userId && cred.holderEmail !== user?.email) return reply.status(403).send({ error: 'Forbidden' })

        const ttlMap: Record<string, number | null> = { none: null, '24h': 86400000, '7d': 604800000, '30d': 2592000000, '90d': 7776000000 }
        const ttl = ttlMap[body.data.expiresIn] ?? null
        const expiresAt = ttl ? new Date(Date.now() + ttl) : null
        const token = generateSecureToken(32)
        const tokenHash = sha256(token)

        const grant = await db.shareGrant.create({ data: { credentialId: cred.id, holderId: profile.id, recipientEmail: body.data.recipientEmail ?? '', tokenHash, expiresAt } })

        audit({ action: 'SHARE_GRANT_CREATED', req, targetType: 'share_grant', targetId: grant.id })

        return reply.status(201).send({ grantId: grant.id, shareUrl: `${env.FRONTEND_URL}/verify?share_token=${token}`, expiresAt })
    })

    app.delete('/me/shares/:grantId', async (req, reply) => {
        const { grantId } = req.params as { grantId: string }
        const profile = await db.holderProfile.findUnique({ where: { userId: req.userId! } })
        if (!profile) return reply.status(404).send({ error: 'Profile not found' })

        const grant = await db.shareGrant.findUnique({ where: { id: grantId }, select: { holderId: true } })
        if (!grant || grant.holderId !== profile.id) return reply.status(404).send({ error: 'Not found' })

        await db.shareGrant.update({ where: { id: grantId }, data: { isRevoked: true, revokedAt: new Date() } })
        audit({ action: 'SHARE_GRANT_REVOKED', req, targetType: 'share_grant', targetId: grantId })

        return reply.status(200).send({ message: 'Share revoked' })
    })

    // ── SELF-VERIFY ───────────────────────────────────────────────
    app.get('/me/self-verify/:credentialId', async (req, reply) => {
        const { credentialId } = req.params as { credentialId: string }
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        const cred = await db.credential.findUnique({ where: { id: credentialId }, select: { holderUserId: true, holderEmail: true } })

        if (!cred) return reply.status(404).send({ error: 'Not found' })
        if (cred.holderUserId !== req.userId && cred.holderEmail !== user?.email) return reply.status(403).send({ error: 'Forbidden' })

        return reply.status(200).send({ credentialId, verifyUrl: `${env.FRONTEND_URL}/verify?credential_id=${credentialId}` })
    })

    // ── VERIFICATION HISTORY ──────────────────────────────────────
    app.get('/me/verifications', async (req, reply) => {
        const query = z.object({ page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(50).default(20) }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit } = query.data
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })

        const holderCreds = await db.credential.findMany({ where: { OR: [{ holderUserId: req.userId }, { holderEmail: user?.email }] }, select: { id: true } })
        const ids = holderCreds.map(c => c.id)

        if (!ids.length) return reply.status(200).send({ logs: [], pagination: { page, limit, total: 0, pages: 0 } })

        const [logs, total] = await db.$transaction([
            db.verificationLog.findMany({ where: { credentialId: { in: ids } }, include: { credential: { select: { credentialType: true, issuer: { select: { institutionName: true } } } } }, orderBy: { verifiedAt: 'desc' }, skip: (page - 1) * limit, take: limit }),
            db.verificationLog.count({ where: { credentialId: { in: ids } } }),
        ])

        return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    // ── PROFILE ───────────────────────────────────────────────────
    app.get('/me', async (req, reply) => {
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { id: true, email: true, firstName: true, lastName: true, phone: true, emailVerified: true, twoFactorEnabled: true, createdAt: true, lastLoginAt: true } })
        if (!user) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ user })
    })

    app.patch('/me', async (req, reply) => {
        const body = z.object({ firstName: z.string().max(100).optional(), lastName: z.string().max(100).optional(), phone: z.string().optional() }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
        const user = await db.user.update({ where: { id: req.userId! }, data: body.data, select: { id: true, firstName: true, lastName: true, phone: true } })
        return reply.status(200).send({ user })
    })

    // ── PASSWORD CHANGE ───────────────────────────────────────────
    app.patch('/me/password', async (req, reply) => {
        const body = z.object({ currentPassword: z.string(), newPassword: z.string().min(8).max(128) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { id: true, passwordHash: true } })
        if (!user) return reply.status(404).send({ error: 'Not found' })

        if (!await verifyPwd(body.data.currentPassword, user.passwordHash)) {
            return reply.status(401).send({ error: 'Unauthorized', message: 'Current password is incorrect' })
        }

        await db.user.update({ where: { id: req.userId! }, data: { passwordHash: await hashPwd(body.data.newPassword), failedLoginCount: 0 } })
        await revokeAllUserTokens(req.userId!)
        audit({ action: 'USER_PASSWORD_CHANGED', req, targetType: 'user', targetId: req.userId! })

        return reply.status(200).send({ message: 'Password updated. Please log in again.' })
    })

    // ── SESSIONS ──────────────────────────────────────────────────
    app.get('/me/sessions', async (req, reply) => {
        const sessions = await db.userSession.findMany({ where: { userId: req.userId!, isActive: true }, select: { id: true, ipAddress: true, userAgent: true, country: true, city: true, lastSeenAt: true, createdAt: true }, orderBy: { lastSeenAt: 'desc' } })
        return reply.status(200).send({ sessions })
    })

    app.delete('/me/sessions/:sessionId', async (req, reply) => {
        const { sessionId } = req.params as { sessionId: string }
        const s = await db.userSession.findUnique({ where: { id: sessionId }, select: { userId: true } })
        if (!s || s.userId !== req.userId) return reply.status(404).send({ error: 'Not found' })
        await db.userSession.update({ where: { id: sessionId }, data: { isActive: false, revokedAt: new Date() } })
        return reply.status(200).send({ message: 'Session revoked' })
    })

    app.delete('/me/sessions', async (req, reply) => {
        await db.userSession.updateMany({ where: { userId: req.userId!, isActive: true }, data: { isActive: false, revokedAt: new Date() } })
        await revokeAllUserTokens(req.userId!)
        return reply.status(200).send({ message: 'All sessions revoked' })
    })

    // ── 2FA ───────────────────────────────────────────────────────
    app.post('/me/2fa/setup', async (req, reply) => {
        const secret = generateTotpSecret()
        const encrypted = encrypt(secret)

        await db.user.update({ where: { id: req.userId! }, data: { twoFactorSecret: encrypted } })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        const totpUri = `otpauth://totp/VeriSure:${user?.email}?secret=${secret}&issuer=VeriSure&algorithm=SHA1&digits=6&period=30`

        return reply.status(200).send({ secret, totpUri })
    })

    app.post('/me/2fa/confirm', async (req, reply) => {
        const body = z.object({ code: z.string().length(6) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error' })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { twoFactorSecret: true } })
        if (!user?.twoFactorSecret) return reply.status(400).send({ error: 'Setup not initiated' })

        const { decrypt: dec } = await import('../../lib/crypto.js')
        const { authenticator } = await import('otplib')
        const secret = dec(user.twoFactorSecret)
        const isValid = authenticator.verify({ token: body.data.code, secret })

        if (!isValid) return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid code' })

        await db.user.update({ where: { id: req.userId! }, data: { twoFactorEnabled: true } })
        return reply.status(200).send({ message: '2FA enabled' })
    })

    app.delete('/me/2fa', async (req, reply) => {
        await db.user.update({ where: { id: req.userId! }, data: { twoFactorEnabled: false, twoFactorSecret: null } })
        return reply.status(200).send({ message: '2FA disabled' })
    })

    // ── ACCOUNT DELETION ──────────────────────────────────────────
    app.delete('/me', async (req, reply) => {
        const body = z.object({ password: z.string() }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Password required to confirm deletion' })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { id: true, passwordHash: true } })
        if (!user) return reply.status(404).send({ error: 'Not found' })
        if (!await verifyPwd(body.data.password, user.passwordHash)) return reply.status(401).send({ error: 'Incorrect password' })

        await db.user.update({ where: { id: req.userId! }, data: { email: `deleted+${req.userId}@verisure.deleted`, passwordHash: 'deleted', firstName: null, lastName: null, phone: null, isActive: false, isSuspended: true } })
        await revokeAllUserTokens(req.userId!)
        audit({ action: 'USER_SUSPENDED', req, targetType: 'user', targetId: req.userId!, metadata: { reason: 'self_deletion' } })

        return reply.status(200).send({ message: 'Account deleted' })
    })
}