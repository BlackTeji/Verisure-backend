import { SignJWT, jwtVerify, type JWTPayload } from 'jose'
import { randomUUID } from 'crypto'
import { env } from '../config/env.js'
import { redis, keys } from './redis.js'
import { sha256 } from './crypto.js'
import { db } from './db.js'
import type { Role } from '@prisma/client'

// ── TYPES ─────────────────────────────────────────────────────
export interface AccessTokenPayload extends JWTPayload {
    sub: string
    email: string
    role: Role
    jti: string
}

export interface RefreshTokenPayload extends JWTPayload {
    sub: string
    jti: string
    family: string
}

const accessSecret = new TextEncoder().encode(env.JWT_ACCESS_SECRET)
const refreshSecret = new TextEncoder().encode(env.JWT_REFRESH_SECRET)

function parseDuration(dur: string): number {
    const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 }
    const m = dur.match(/^(\d+)([smhd])$/)
    if (!m?.[1] || !m?.[2]) throw new Error(`Invalid duration: ${dur}`)
    return parseInt(m[1]) * (units[m[2]] ?? 1)
}

// ── ISSUE ─────────────────────────────────────────────────────
export async function issueAccessToken(p: { userId: string; email: string; role: Role }): Promise<string> {
    const jti = randomUUID()
    const exp = Math.floor(Date.now() / 1000) + parseDuration(env.JWT_ACCESS_EXPIRES_IN)
    return new SignJWT({ sub: p.userId, email: p.email, role: p.role, jti })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('verisure.ng')
        .setAudience('verisure-api')
        .setExpirationTime(exp)
        .sign(accessSecret)
}

export async function issueRefreshToken(p: {
    userId: string
    family?: string
    ip?: string
    agent?: string
}): Promise<{ token: string; tokenHash: string; family: string; expiresAt: Date }> {
    const jti = randomUUID()
    const family = p.family ?? randomUUID()
    const exp = Math.floor(Date.now() / 1000) + parseDuration(env.JWT_REFRESH_EXPIRES_IN)

    const token = await new SignJWT({ sub: p.userId, jti, family })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('verisure.ng')
        .setAudience('verisure-refresh')
        .setExpirationTime(exp)
        .sign(refreshSecret)

    const tokenHash = sha256(token)
    const expiresAt = new Date(exp * 1000)

    await db.refreshToken.create({
        data: { userId: p.userId, tokenHash, family, expiresAt, ipAddress: p.ip ?? null, userAgent: p.agent ?? null },
    })

    return { token, tokenHash, family, expiresAt }
}

// ── VERIFY ────────────────────────────────────────────────────
export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const { payload } = await jwtVerify(token, accessSecret, { issuer: 'verisure.ng', audience: 'verisure-api' })
    const jti = payload.jti as string
    const blacklisted = await redis.exists(keys.tokenBlacklist(jti))
    if (blacklisted) throw new Error('Token revoked')
    return payload as AccessTokenPayload
}

export async function verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    const { payload } = await jwtVerify(token, refreshSecret, { issuer: 'verisure.ng', audience: 'verisure-refresh' })
    const tokenHash = sha256(token)
    const stored = await db.refreshToken.findUnique({ where: { tokenHash } })

    if (!stored) {
        const family = payload['family'] as string | undefined
        if (family) {
            await db.refreshToken.updateMany({ where: { family, isRevoked: false }, data: { isRevoked: true, revokedAt: new Date() } })
        }
        throw new Error('Invalid refresh token — family revoked')
    }

    if (stored.isRevoked) throw new Error('Refresh token revoked')
    if (stored.expiresAt < new Date()) throw new Error('Refresh token expired')

    await db.refreshToken.update({ where: { id: stored.id }, data: { isRevoked: true, revokedAt: new Date() } })

    return payload as RefreshTokenPayload
}

// ── REVOKE ────────────────────────────────────────────────────
export async function blacklistAccessToken(jti: string, expiresAt: number): Promise<void> {
    const ttl = expiresAt - Math.floor(Date.now() / 1000)
    if (ttl > 0) await redis.setex(keys.tokenBlacklist(jti), ttl, '1')
}

export async function revokeAllUserTokens(userId: string): Promise<void> {
    await db.refreshToken.updateMany({ where: { userId, isRevoked: false }, data: { isRevoked: true, revokedAt: new Date() } })
}