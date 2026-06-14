import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { scrypt, randomBytes } from 'crypto'
import { promisify } from 'util'
import { db } from '../../lib/db.js'
import { issueAccessToken, issueRefreshToken, verifyRefreshToken, blacklistAccessToken, revokeAllUserTokens } from '../../lib/jwt.js'
import { sha256, generateSecureToken } from '../../lib/crypto.js'
import { emailQueue } from '../../lib/queue.js'
import { authenticate } from '../../hooks/authenticate.js'
import { audit } from '../../hooks/audit.js'
import { env } from '../../config/env.js'

const scryptAsync = promisify(scrypt)
const COOKIE = 'vrs_refresh'

async function hashPassword(p: string): Promise<string> {
    const salt = randomBytes(32).toString('hex')
    const key = await scryptAsync(p, salt, 64) as Buffer
    return `${salt}:${key.toString('hex')}`
}

async function verifyPassword(p: string, stored: string): Promise<boolean> {
    const [salt, hash] = stored.split(':')
    if (!salt || !hash) return false
    const key = await scryptAsync(p, salt, 64) as Buffer
    const ref = Buffer.from(hash, 'hex')
    if (key.length !== ref.length) return false
    let diff = 0
    for (let i = 0; i < key.length; i++) diff |= (key[i] ?? 0) ^ (ref[i] ?? 0)
    return diff === 0
}

function setRefreshCookie(reply: any, token: string, expiresAt: Date): void {
    reply.setCookie(COOKIE, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/api/v1/auth/refresh',
        expires: expiresAt,
    })
}

function clearRefreshCookie(reply: any): void {
    reply.clearCookie(COOKIE, {
        path: '/api/v1/auth/refresh',
        sameSite: 'strict',
        secure: true,
    })
}

const signupSchema = z.object({
    email: z.string().email().toLowerCase(),
    password: z.string().min(8).max(128),
    role: z.enum(['HOLDER', 'ISSUER', 'VERIFIER']),
    firstName: z.string().max(100).optional(),
    lastName: z.string().max(100).optional(),
    phone: z.string().optional(),
    institutionName: z.string().optional(),
    institutionType: z.string().optional(),
    registrationNumber: z.string().optional(),
    contactFirstName: z.string().optional(),
    contactLastName: z.string().optional(),
    contactTitle: z.string().optional(),
    officialEmail: z.string().email().optional(),
    annualVolume: z.string().optional(),
    organisationName: z.string().optional(),
    organisationType: z.string().optional(),
    teamSize: z.string().optional(),
    monthlyVolume: z.string().optional(),
    claimToken: z.string().max(256).optional(),
    credentialId: z.string().max(64).optional(),
})

export default async function authRoutes(app: FastifyInstance) {

    app.post('/signup', async (req, reply) => {
        try {
            const body = signupSchema.safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })
            const d = body.data

            const existing = await db.user.findUnique({ where: { email: d.email } })
            if (existing) return reply.status(409).send({ error: 'Conflict', message: 'Account already exists' })

            if (d.role === 'ISSUER' && (!d.institutionName || !d.officialEmail || !d.contactFirstName || !d.contactLastName)) {
                return reply.status(400).send({ error: 'Validation error', message: 'Institution details required' })
            }

            let claimedCredential: { id: string } | null = null
            if (d.role === 'HOLDER' && d.claimToken && d.credentialId) {
                claimedCredential = await db.credential.findFirst({
                    where: {
                        id: d.credentialId,
                        claimTokenHash: sha256(d.claimToken),
                        holderEmail: d.email,
                        holderUserId: null,
                        claimTokenExpiresAt: { gt: new Date() },
                    },
                    select: { id: true },
                })
            }

            const passwordHash = await hashPassword(d.password)

            const result = await db.$transaction(async tx => {
                const u = await tx.user.create({
                    data: {
                        email: d.email,
                        passwordHash,
                        role: d.role,
                        firstName: d.firstName ?? null,
                        lastName: d.lastName ?? null,
                        phone: d.phone ?? null,
                        emailVerified: !!claimedCredential,
                        emailVerifiedAt: claimedCredential ? new Date() : null,
                    },
                    select: { id: true, email: true, role: true },
                })
                if (d.role === 'HOLDER') await tx.holderProfile.create({ data: { userId: u.id } })
                if (d.role === 'ISSUER') await tx.issuerProfile.create({ data: { userId: u.id, institutionName: d.institutionName!, institutionType: d.institutionType ?? '', registrationNumber: d.registrationNumber ?? null, officialEmail: d.officialEmail!, phone: d.phone ?? null, contactFirstName: d.contactFirstName!, contactLastName: d.contactLastName!, contactTitle: d.contactTitle ?? null, annualVolume: d.annualVolume ?? null, status: 'PENDING' } })
                if (d.role === 'VERIFIER') await tx.verifierProfile.create({ data: { userId: u.id, organisationName: d.organisationName ?? '', organisationType: d.organisationType ?? '', teamSize: d.teamSize ?? null, monthlyVolume: d.monthlyVolume ?? null } })

                let linkedCount = 0
                if (claimedCredential) {
                    const linked = await tx.credential.updateMany({
                        where: { holderEmail: d.email, holderUserId: null },
                        data: { holderUserId: u.id, claimTokenHash: null, claimTokenExpiresAt: null },
                    })
                    linkedCount = linked.count
                }

                return { user: u, linkedCount }
            })

            const user = result.user

            if (!claimedCredential) {
                const token = generateSecureToken()
                const tokenHash = sha256(token)
                await db.emailVerificationToken.create({ data: { userId: user.id, tokenHash, expiresAt: new Date(Date.now() + 86_400_000) } })

                await emailQueue.add('email_verification', {
                    type: 'email_verification',
                    to: user.email,
                    name: d.firstName ?? d.institutionName ?? 'there',
                    data: { verifyUrl: `${env.FRONTEND_URL}/pages/verify-email.html?token=${token}` },
                })
            }

            audit({
                action: 'USER_SIGNUP',
                req,
                targetType: 'user',
                targetId: user.id,
                metadata: {
                    role: user.role,
                    claimedViaToken: !!claimedCredential,
                    linkedCredentials: result.linkedCount,
                },
            })

            const message = d.role === 'ISSUER'
                ? 'Application received. You will be notified when reviewed.'
                : claimedCredential
                    ? `Account created. ${result.linkedCount} credential${result.linkedCount === 1 ? ' has' : 's have'} been added to your wallet.`
                    : 'Account created. Check your email to verify.'

            return reply.status(201).send({
                message,
                userId: user.id,
                role: user.role,
                emailVerified: !!claimedCredential,
                linkedCredentials: result.linkedCount,
            })
        } catch (err) {
            app.log.error({ err }, 'Signup error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.post('/login', async (req, reply) => {
        try {
            const body = z.object({
                email: z.string().email().toLowerCase(),
                password: z.string(),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

            const user = await db.user.findUnique({
                where: { email: body.data.email },
                select: {
                    id: true, email: true, role: true, passwordHash: true,
                    firstName: true,
                    isSuspended: true, isActive: true, failedLoginCount: true,
                    lockedUntil: true, emailVerified: true,
                },
            })

            const isValid = user
                ? await verifyPassword(body.data.password, user.passwordHash)
                : (await hashPassword('dummy') && false)

            if (!user || !isValid) {
                if (user) {
                    await db.user.update({
                        where: { id: user.id },
                        data: {
                            failedLoginCount: { increment: 1 },
                            lockedUntil: user.failedLoginCount >= 9
                                ? new Date(Date.now() + 900_000)
                                : undefined,
                        },
                    })
                }
                return reply.status(401).send({ error: 'Unauthorized', message: 'Incorrect email or password' })
            }

            if (user.isSuspended) {
                return reply.status(403).send({ error: 'Forbidden', message: 'Account suspended. Contact support.' })
            }

            if (user.lockedUntil && user.lockedUntil > new Date()) {
                return reply.status(429).send({
                    error: 'Locked',
                    message: `Account locked. Try in ${Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60_000)} minutes.`,
                })
            }

            await db.user.update({
                where: { id: user.id },
                data: { failedLoginCount: 0, lockedUntil: null, lastLoginAt: new Date(), lastLoginIp: req.ip },
            })

            const userAgent = req.headers['user-agent']?.slice(0, 500) ?? 'Unknown'
            const clientIp = req.ip

            const priorSession = await db.userSession.findFirst({
                where: { userId: user.id, ipAddress: clientIp },
                select: { id: true },
            })

            await db.userSession.create({
                data: { userId: user.id, ipAddress: clientIp, userAgent, isActive: true },
            })

            if (!priorSession) {
                const loginTime = new Date().toLocaleString('en-NG', {
                    timeZone: 'Africa/Lagos',
                    dateStyle: 'medium',
                    timeStyle: 'short',
                })
                emailQueue.add('new_device_alert', {
                    type: 'new_device_alert',
                    to: user.email,
                    data: {
                        name: user.firstName ?? 'there',
                        email: user.email,
                        ipAddress: clientIp,
                        userAgent: userAgent.slice(0, 120),
                        loginTime,
                        accountUrl: `${env.FRONTEND_URL}/pages/login.html`,
                    },
                }).catch(() => { })
            }

            const [accessToken, { token: refreshToken, expiresAt }] = await Promise.all([
                issueAccessToken({ userId: user.id, email: user.email, role: user.role }),
                issueRefreshToken({ userId: user.id, ip: req.ip, agent: req.headers['user-agent'] }),
            ])

            setRefreshCookie(reply, refreshToken, expiresAt)
            audit({ action: 'USER_LOGIN', req, targetType: 'user', targetId: user.id })

            return reply.status(200).send({ accessToken, refreshToken, user: { id: user.id, email: user.email, role: user.role } })

        } catch (err) {
            app.log.error({ err }, 'Login error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.post('/refresh', async (req, reply) => {
        const token = (req.cookies as Record<string, string>)[COOKIE]
            ?? (z.object({ refreshToken: z.string() }).safeParse(req.body).success ? (req.body as any).refreshToken : null)

        if (!token) return reply.status(401).send({ error: 'Unauthorized', message: 'Refresh token required' })

        try {
            const payload = await verifyRefreshToken(token)
            const user = await db.user.findUnique({
                where: { id: payload.sub as string },
                select: { id: true, email: true, role: true, isSuspended: true },
            })

            if (!user || user.isSuspended) {
                clearRefreshCookie(reply)
                return reply.status(401).send({ error: 'Unauthorized' })
            }

            const [accessToken, { token: newRefresh, expiresAt }] = await Promise.all([
                issueAccessToken({ userId: user.id, email: user.email, role: user.role }),
                issueRefreshToken({ userId: user.id, family: payload.family, ip: req.ip, agent: req.headers['user-agent'] }),
            ])

            setRefreshCookie(reply, newRefresh, expiresAt)
            audit({ action: 'TOKEN_REFRESHED', req, targetType: 'user', targetId: user.id })

            return reply.status(200).send({ accessToken, refreshToken: newRefresh })

        } catch {
            clearRefreshCookie(reply)
            return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid refresh token' })
        }
    })

    app.post('/logout', { preHandler: authenticate }, async (req, reply) => {
        try {
            const token = req.headers.authorization?.slice(7)

            if (token) {
                try {
                    const { jwtVerify } = await import('jose')
                    const secret = new TextEncoder().encode(env.JWT_ACCESS_SECRET)
                    const { payload } = await jwtVerify(token, secret)
                    if (payload.jti && payload.exp) await blacklistAccessToken(payload.jti, payload.exp)
                } catch { }
            }

            clearRefreshCookie(reply)

            if (req.userId) {
                await db.refreshToken.updateMany({
                    where: { userId: req.userId, isRevoked: false },
                    data: { isRevoked: true, revokedAt: new Date() },
                })
                await db.userSession.updateMany({
                    where: { userId: req.userId, ipAddress: req.ip, isActive: true },
                    data: { isActive: false, revokedAt: new Date() },
                }).catch(() => { })
                audit({ action: 'USER_LOGOUT', req, targetType: 'user', targetId: req.userId })
            }

            return reply.status(200).send({ message: 'Logged out' })
        } catch (err) {
            app.log.error({ err }, 'Logout error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.get('/verify-email', async (req, reply) => {
        try {
            const token = (req.query as Record<string, string>)['token']
            if (!token) return reply.status(400).send({ error: 'Bad request', message: 'Token required' })

            const record = await db.emailVerificationToken.findUnique({ where: { tokenHash: sha256(token) } })

            if (!record) {
                return reply.status(410).send({ error: 'Gone', message: 'Invalid or expired link' })
            }

            if (record.usedAt) {
                return reply.status(410).send({ error: 'Gone', message: 'This link has already been used' })
            }

            if (record.expiresAt < new Date()) {
                return reply.status(410).send({ error: 'Gone', message: 'This verification link has expired' })
            }

            await db.$transaction([
                db.emailVerificationToken.update({ where: { id: record.id }, data: { usedAt: new Date() } }),
                db.user.update({ where: { id: record.userId }, data: { emailVerified: true, emailVerifiedAt: new Date() } }),
            ])

            const user = await db.user.findUnique({ where: { id: record.userId }, select: { email: true, role: true } })

            let linkedCredentials = 0
            if (user?.role === 'HOLDER') {
                const linked = await db.credential.updateMany({
                    where: { holderEmail: user.email, holderUserId: null },
                    data: { holderUserId: record.userId, claimTokenHash: null, claimTokenExpiresAt: null },
                }).catch(() => ({ count: 0 }))
                linkedCredentials = linked.count
            }

            return reply.status(200).send({ message: 'Email verified', role: user?.role ?? null, linkedCredentials })
        } catch (err) {
            app.log.error({ err }, 'Email verification error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.post('/resend-verification', async (req, reply) => {
        try {
            const body = z.object({ email: z.string().email().toLowerCase() }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error' })

            const user = await db.user.findUnique({
                where: { email: body.data.email },
                select: { id: true, email: true, emailVerified: true, firstName: true, role: true },
            })

            if (user && !user.emailVerified) {
                await db.emailVerificationToken.updateMany({
                    where: { userId: user.id, usedAt: null },
                    data: { usedAt: new Date() },
                })

                const token = generateSecureToken()
                const tokenHash = sha256(token)
                await db.emailVerificationToken.create({
                    data: { userId: user.id, tokenHash, expiresAt: new Date(Date.now() + 86_400_000) },
                })

                await emailQueue.add('email_verification_resend', {
                    type: 'email_verification',
                    to: user.email,
                    name: user.firstName ?? 'there',
                    data: { verifyUrl: `${env.FRONTEND_URL}/pages/verify-email.html?token=${token}` },
                })
            }

            return reply.status(200).send({ message: 'If an unverified account exists for that address, a new link has been sent.' })
        } catch (err) {
            app.log.error({ err }, 'Resend verification error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.post('/forgot-password', async (req, reply) => {
        try {
            const body = z.object({ email: z.string().email().toLowerCase() }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error' })

            const user = await db.user.findUnique({ where: { email: body.data.email } })
            if (user) {
                const token = generateSecureToken()
                const tokenHash = sha256(token)
                await db.passwordResetToken.create({
                    data: { userId: user.id, tokenHash, expiresAt: new Date(Date.now() + 3_600_000) },
                })
                await emailQueue.add('password_reset', {
                    type: 'password_reset',
                    to: user.email,
                    name: user.firstName ?? 'there',
                    data: { resetUrl: `${env.FRONTEND_URL}/pages/reset-password.html?token=${token}` },
                })
            }

            return reply.status(200).send({ message: 'If an account exists, a reset link has been sent.' })
        } catch (err) {
            app.log.error({ err }, 'Forgot password error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.get('/validate-reset-token', async (req, reply) => {
        try {
            const token = (req.query as Record<string, string>)['token']
            if (!token) return reply.status(400).send({ error: 'Bad request', message: 'Token required' })

            const record = await db.passwordResetToken.findUnique({ where: { tokenHash: sha256(token) } })
            if (!record || record.usedAt || record.expiresAt < new Date()) {
                return reply.status(400).send({ error: 'Bad request', message: 'Invalid or expired link' })
            }

            return reply.status(200).send({ valid: true })
        } catch (err) {
            app.log.error({ err }, 'Validate reset token error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })

    app.post('/reset-password', async (req, reply) => {
        try {
            const body = z.object({
                token: z.string(),
                password: z.string().min(8).max(128),
            }).safeParse(req.body)
            if (!body.success) return reply.status(400).send({ error: 'Validation error' })

            const record = await db.passwordResetToken.findUnique({ where: { tokenHash: sha256(body.data.token) } })
            if (!record || record.usedAt || record.expiresAt < new Date()) {
                return reply.status(400).send({ error: 'Bad request', message: 'Invalid or expired link' })
            }

            const passwordHash = await hashPassword(body.data.password)

            await db.$transaction([
                db.passwordResetToken.update({ where: { id: record.id }, data: { usedAt: new Date() } }),
                db.user.update({ where: { id: record.userId }, data: { passwordHash, failedLoginCount: 0, lockedUntil: null } }),
            ])

            await revokeAllUserTokens(record.userId)

            await db.userSession.updateMany({
                where: { userId: record.userId, isActive: true },
                data: { isActive: false, revokedAt: new Date() },
            }).catch(() => { })

            const authHeader = req.headers.authorization
            if (authHeader?.startsWith('Bearer ')) {
                try {
                    const { jwtVerify } = await import('jose')
                    const secret = new TextEncoder().encode(env.JWT_ACCESS_SECRET)
                    const { payload } = await jwtVerify(authHeader.slice(7), secret)
                    if (payload.jti && payload.exp) await blacklistAccessToken(payload.jti, payload.exp)
                } catch { }
            }

            audit({ action: 'USER_PASSWORD_CHANGED', req, targetType: 'user', targetId: record.userId })

            return reply.status(200).send({ message: 'Password reset. Please log in.' })
        } catch (err) {
            app.log.error({ err }, 'Reset password error')
            return reply.status(500).send({ error: 'Server error', message: 'Something went wrong. Please try again.' })
        }
    })
}