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
import { emailQueue } from '../../lib/queue.js'
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

function serialiseCredential<T extends { blockNumber: bigint | null; claimTokenHash?: string | null; claimTokenExpiresAt?: Date | null }>(c: T) {
    const { claimTokenHash, claimTokenExpiresAt, ...rest } = c
    return {
        ...rest,
        blockNumber: c.blockNumber != null ? c.blockNumber.toString() : null,
    }
}

export default async function holderRoutes(app: FastifyInstance) {

    app.addHook('preHandler', authenticate)
    app.addHook('preHandler', requireHolder)

    app.get('/me/credentials', async (req, reply) => {
        const query = z.object({
            status: z.enum(['ACTIVE', 'REVOKED', 'FROZEN', 'EXPIRED']).optional(),
            sort: z.enum(['newest', 'oldest', 'issuer']).default('newest'),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })

        const aliases = await db.userEmailAlias.findMany({
            where: { userId: req.userId!, verifiedAt: { not: null } },
            select: { email: true },
        })
        const allEmails = [user?.email, ...aliases.map((a: any) => a.email)].filter(Boolean)

        const where: any = {
            OR: [
                { holderUserId: req.userId },
                { holderEmail: { in: allEmails } },
            ],
            ...(query.data.status ? { status: query.data.status } : {}),
        }

        const orderBy = query.data.sort === 'oldest'
            ? { createdAt: 'asc' as const }
            : query.data.sort === 'issuer'
                ? { issuer: { institutionName: 'asc' as const } }
                : { createdAt: 'desc' as const }

        const credentials = await db.credential.findMany({
            where,
            include: {
                issuer: { select: { id: true, institutionName: true, institutionType: true, status: true } },
                _count: { select: { verifications: true } },
            },
            orderBy,
        })

        const unlinkted = credentials.filter(c => !c.holderUserId && allEmails.includes(c.holderEmail))
        if (unlinkted.length) {
            await db.credential.updateMany({
                where: { id: { in: unlinkted.map(c => c.id) } },
                data: { holderUserId: req.userId },
            })
        }

        const now = new Date()
        const enriched = credentials.map(c => {
            const serialised = serialiseCredential(c)
            return {
                ...serialised,
                status: c.expiryDate && c.expiryDate < now && c.status === 'ACTIVE' ? 'EXPIRED' : c.status,
                expiresInDays: c.expiryDate ? Math.ceil((c.expiryDate.getTime() - now.getTime()) / 86400000) : null,
            }
        })

        return reply.status(200).send({ credentials: enriched })
    })

    app.get('/me/credentials/:id', async (req, reply) => {
        const { id } = req.params as { id: string }
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })

        const aliases = await db.userEmailAlias.findMany({
            where: { userId: req.userId!, verifiedAt: { not: null } },
            select: { email: true },
        })
        const allEmails = [user?.email, ...aliases.map((a: any) => a.email)].filter(Boolean)

        const cred = await db.credential.findUnique({
            where: { id },
            include: { issuer: { select: { id: true, institutionName: true, institutionType: true, status: true } } },
        })

        if (!cred) return reply.status(404).send({ error: 'Not found' })

        const owns = cred.holderUserId === req.userId || allEmails.includes(cred.holderEmail)
        if (!owns) return reply.status(403).send({ error: 'Forbidden' })

        if (!cred.holderUserId && allEmails.includes(cred.holderEmail)) {
            await db.credential.update({ where: { id }, data: { holderUserId: req.userId } })
        }

        return reply.status(200).send({ credential: serialiseCredential(cred) })
    })

    app.get('/me/shares', async (req, reply) => {
        const profile = await db.holderProfile.findUnique({ where: { userId: req.userId! }, select: { id: true } })
        if (!profile) return reply.status(404).send({ error: 'Profile not found' })

        const grants = await db.shareGrant.findMany({
            where: { holderId: profile.id },
            include: { credential: { select: { id: true, credentialType: true, issuer: { select: { institutionName: true } } } } },
            orderBy: { createdAt: 'desc' },
        })

        const now = new Date()
        const enriched = grants.map(({ tokenHash: _th, ...g }) => ({
            ...g,
            isExpired: g.expiresAt ? g.expiresAt < now : false,
            isActive: !g.isRevoked && (!g.expiresAt || g.expiresAt >= now),
        }))

        return reply.status(200).send({ grants: enriched })
    })

    app.post('/me/shares', async (req, reply) => {
        const body = z.object({
            credentialId: z.string(),
            recipientEmail: z.string().email().toLowerCase().optional(),
            expiresIn: z.enum(['none', '24h', '7d', '30d', '90d']).default('none'),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true, firstName: true, lastName: true } })
        const aliases = await db.userEmailAlias.findMany({
            where: { userId: req.userId!, verifiedAt: { not: null } },
            select: { email: true },
        })
        const allEmails = [user?.email, ...aliases.map((a: any) => a.email)].filter(Boolean)

        const profile = await db.holderProfile.findUnique({ where: { userId: req.userId! } })
        if (!profile) return reply.status(404).send({ error: 'Profile not found' })

        const cred = await db.credential.findUnique({
            where: { id: body.data.credentialId },
            select: {
                id: true, holderUserId: true, holderEmail: true, credentialType: true,
                issuer: { select: { institutionName: true } },
            },
        })
        if (!cred) return reply.status(404).send({ error: 'Credential not found' })
        if (cred.holderUserId !== req.userId && !allEmails.includes(cred.holderEmail)) {
            return reply.status(403).send({ error: 'Forbidden' })
        }

        const ttlMap: Record<string, number | null> = { none: null, '24h': 86400000, '7d': 604800000, '30d': 2592000000, '90d': 7776000000 }
        const ttl = ttlMap[body.data.expiresIn] ?? null
        const expiresAt = ttl ? new Date(Date.now() + ttl) : null
        const token = generateSecureToken(32)
        const tokenHash = sha256(token)

        const grant = await db.shareGrant.create({
            data: { credentialId: cred.id, holderId: profile.id, recipientEmail: body.data.recipientEmail ?? '', tokenHash, expiresAt },
        })

        const shareUrl = `${env.FRONTEND_URL}/pages/verify.html?share_token=${token}`

        if (body.data.recipientEmail) {
            const holderName = [user?.firstName, user?.lastName].filter(Boolean).join(' ') || user?.email || 'A VeriSure user'
            await emailQueue.add('share_grant_created', {
                type: 'share_grant_created',
                to: body.data.recipientEmail,
                data: {
                    holderName,
                    credentialType: cred.credentialType,
                    issuerName: cred.issuer.institutionName,
                    shareUrl,
                    expiresAt: expiresAt ? expiresAt.toLocaleDateString('en-NG', { day: 'numeric', month: 'long', year: 'numeric' }) : null,
                },
            }).catch((e: any) => app.log.error({ err: e }, 'Share grant email failed'))
        }

        audit({ action: 'SHARE_GRANT_CREATED', req, targetType: 'share_grant', targetId: grant.id })

        return reply.status(201).send({
            grantId: grant.id,
            shareUrl,
            expiresAt,
        })
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

    app.get('/me/self-verify/:credentialId', async (req, reply) => {
        const { credentialId } = req.params as { credentialId: string }
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        const aliases = await db.userEmailAlias.findMany({
            where: { userId: req.userId!, verifiedAt: { not: null } },
            select: { email: true },
        })
        const allEmails = [user?.email, ...aliases.map((a: any) => a.email)].filter(Boolean)

        const cred = await db.credential.findUnique({ where: { id: credentialId }, select: { holderUserId: true, holderEmail: true } })
        if (!cred) return reply.status(404).send({ error: 'Not found' })
        if (cred.holderUserId !== req.userId && !allEmails.includes(cred.holderEmail)) {
            return reply.status(403).send({ error: 'Forbidden' })
        }

        return reply.status(200).send({ credentialId, verifyUrl: `${env.FRONTEND_URL}/pages/verify.html?credential_id=${credentialId}` })
    })

    app.get('/me/verifications', async (req, reply) => {
        const query = z.object({
            page: z.coerce.number().int().min(1).default(1),
            limit: z.coerce.number().int().min(1).max(50).default(20),
        }).safeParse(req.query)
        if (!query.success) return reply.status(400).send({ error: 'Validation error' })

        const { page, limit } = query.data
        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        const aliases = await db.userEmailAlias.findMany({
            where: { userId: req.userId!, verifiedAt: { not: null } },
            select: { email: true },
        })
        const allEmails = [user?.email, ...aliases.map((a: any) => a.email)].filter(Boolean)

        const holderCreds = await db.credential.findMany({
            where: { OR: [{ holderUserId: req.userId }, { holderEmail: { in: allEmails } }] },
            select: { id: true },
        })
        const ids = holderCreds.map(c => c.id)

        if (!ids.length) return reply.status(200).send({ logs: [], pagination: { page, limit, total: 0, pages: 0 } })

        const [logs, total] = await db.$transaction([
            db.verificationLog.findMany({
                where: { credentialId: { in: ids } },
                include: {
                    credential: { select: { credentialType: true, issuer: { select: { institutionName: true } } } },
                    verifier: { select: { organisationName: true } },
                },
                orderBy: { verifiedAt: 'desc' },
                skip: (page - 1) * limit,
                take: limit,
            }),
            db.verificationLog.count({ where: { credentialId: { in: ids } } }),
        ])

        return reply.status(200).send({ logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } })
    })

    app.get('/me', async (req, reply) => {
        const user = await db.user.findUnique({
            where: { id: req.userId! },
            select: { id: true, email: true, firstName: true, lastName: true, phone: true, emailVerified: true, twoFactorEnabled: true, createdAt: true, lastLoginAt: true },
        })
        if (!user) return reply.status(404).send({ error: 'Not found' })
        return reply.status(200).send({ user })
    })

    app.patch('/me', async (req, reply) => {
        const body = z.object({
            firstName: z.string().max(100).optional(),
            lastName: z.string().max(100).optional(),
            phone: z.string().optional(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
        const user = await db.user.update({ where: { id: req.userId! }, data: body.data, select: { id: true, firstName: true, lastName: true, phone: true } })
        return reply.status(200).send({ user })
    })

    app.get('/me/aliases', async (req, reply) => {
        const aliases = await db.userEmailAlias.findMany({
            where: { userId: req.userId! },
            select: {
                id: true,
                email: true,
                verifiedAt: true,
                linkedCredentialCount: true,
                createdAt: true,
            },
            orderBy: { createdAt: 'asc' },
        })
        return reply.status(200).send({ aliases })
    })

    app.post('/me/aliases', async (req, reply) => {
        const body = z.object({
            email: z.string().email().toLowerCase(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const newEmail = body.data.email

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { email: true } })
        if (user?.email === newEmail) {
            return reply.status(409).send({ error: 'Conflict', message: 'This is already your primary email address.' })
        }

        const existingUser = await db.user.findUnique({ where: { email: newEmail } })
        if (existingUser) {
            return reply.status(409).send({ error: 'Conflict', message: 'This email address is already registered as a primary account.' })
        }

        const existingAlias = await db.userEmailAlias.findUnique({ where: { email: newEmail } })
        if (existingAlias) {
            return reply.status(409).send({ error: 'Conflict', message: 'This email is already linked to an account.' })
        }

        const count = await db.userEmailAlias.count({ where: { userId: req.userId! } })
        if (count >= 10) {
            return reply.status(429).send({ error: 'Limit exceeded', message: 'Maximum of 10 email aliases per account.' })
        }

        const token = generateSecureToken()
        const tokenHash = sha256(token)
        const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000)

        await db.userEmailAlias.upsert({
            where: { email: newEmail },
            create: {
                userId: req.userId!,
                email: newEmail,
                verificationTokenHash: tokenHash,
                verificationExpiresAt: expiresAt,
            },
            update: {
                userId: req.userId!,
                verificationTokenHash: tokenHash,
                verificationExpiresAt: expiresAt,
                verifiedAt: null,
            },
        })

        await emailQueue.add('alias_verification', {
            type: 'email_verification',
            to: newEmail,
            name: user?.email ?? 'there',
            data: {
                verifyUrl: `${env.FRONTEND_URL}/pages/verify-email.html?alias_token=${token}`,
                isPrimaryEmail: false,
            },
        }).catch((e: any) => app.log.error({ err: e }, 'Alias verification email failed'))

        return reply.status(201).send({ message: `Verification email sent to ${newEmail}. Link expires in 72 hours.` })
    })

    app.get('/me/aliases/verify', async (req, reply) => {
        const token = (req.query as Record<string, string>)['alias_token']
        if (!token) return reply.status(400).send({ error: 'Bad request', message: 'Token required.' })

        const tokenHash = sha256(token)
        const alias = await db.userEmailAlias.findFirst({
            where: { verificationTokenHash: tokenHash },
        })

        if (!alias) return reply.status(400).send({ error: 'Bad request', message: 'Invalid or expired link.' })
        if (alias.verifiedAt) return reply.status(200).send({ message: 'Already verified.', email: alias.email })
        if (alias.verificationExpiresAt && alias.verificationExpiresAt < new Date()) {
            return reply.status(400).send({ error: 'Expired', message: 'This link has expired. Add the email again to get a new link.' })
        }

        await db.userEmailAlias.update({
            where: { id: alias.id },
            data: {
                verifiedAt: new Date(),
                verificationTokenHash: null,
                verificationExpiresAt: null,
            },
        })

        const claimed = await claimCredentialsForAlias(alias.userId, alias.email)

        if (claimed > 0) {
            await db.userEmailAlias.update({
                where: { id: alias.id },
                data: { linkedCredentialCount: claimed },
            })
        }

        return reply.status(200).send({
            message: 'Email verified and added to your account.',
            email: alias.email,
            credentialsClaimed: claimed,
        })
    })

    app.delete('/me/aliases/:aliasId', async (req, reply) => {
        const { aliasId } = req.params as { aliasId: string }

        const alias = await db.userEmailAlias.findFirst({
            where: { id: aliasId, userId: req.userId! },
        })
        if (!alias) return reply.status(404).send({ error: 'Not found' })

        const exclusiveCredentials = await db.credential.count({
            where: {
                holderEmail: alias.email,
                holderUserId: null,
            },
        })

        if (exclusiveCredentials > 0) {
            return reply.status(409).send({
                error: 'Conflict',
                message: `This alias has ${exclusiveCredentials} credential(s) exclusively linked to it. Claim them first before removing this alias.`,
            })
        }

        await db.userEmailAlias.delete({ where: { id: aliasId } })

        return reply.status(200).send({ message: 'Alias removed.' })
    })

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
        audit({ action: 'USER_PASSWORD_CHANGED', req, targetType: 'user', targetId: req.userId! })

        return reply.status(200).send({ message: 'Password updated. Please log in again.' })
    })

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
        return reply.status(200).send({ message: 'Session revoked' })
    })

    app.delete('/me/sessions', async (req, reply) => {
        await db.userSession.updateMany({ where: { userId: req.userId!, isActive: true }, data: { isActive: false, revokedAt: new Date() } })
        await revokeAllUserTokens(req.userId!)
        return reply.status(200).send({ message: 'All sessions revoked' })
    })

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

    app.delete('/me', async (req, reply) => {
        const body = z.object({ password: z.string() }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Password required to confirm deletion' })

        const user = await db.user.findUnique({ where: { id: req.userId! }, select: { id: true, passwordHash: true } })
        if (!user) return reply.status(404).send({ error: 'Not found' })
        if (!await verifyPwd(body.data.password, user.passwordHash)) return reply.status(401).send({ error: 'Incorrect password' })

        await db.user.update({
            where: { id: req.userId! },
            data: {
                email: `deleted+${req.userId}@verisure.deleted`,
                passwordHash: 'deleted',
                firstName: null,
                lastName: null,
                phone: null,
                isActive: false,
                isSuspended: true,
            },
        })
        await revokeAllUserTokens(req.userId!)
        audit({ action: 'USER_SUSPENDED', req, targetType: 'user', targetId: req.userId!, metadata: { reason: 'self_deletion' } })

        return reply.status(200).send({ message: 'Account deleted' })
    })
}

async function claimCredentialsForAlias(userId: string, email: string): Promise<number> {
    const unlinked = await db.credential.findMany({
        where: { holderEmail: email, holderUserId: null },
        select: { id: true },
    })

    if (!unlinked.length) return 0

    await db.credential.updateMany({
        where: { id: { in: unlinked.map(c => c.id) } },
        data: { holderUserId: userId, claimTokenHash: null, claimTokenExpiresAt: null },
    })

    return unlinked.length
}