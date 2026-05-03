import type { FastifyRequest, FastifyReply } from 'fastify'
import { verifyAccessToken } from '../lib/jwt.js'
import { redis, keys } from '../lib/redis.js'
import { db } from '../lib/db.js'
import { sha256 } from '../lib/crypto.js'
import type { Role } from '@prisma/client'

declare module 'fastify' {
    interface FastifyRequest {
        userId?: string
        userEmail?: string
        userRole?: Role
        issuerId?: string
        verifierId?: string
        apiKeyId?: string
    }
}

// ── JWT ───────────────────────────────────────────────────────
export async function authenticate(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const header = req.headers.authorization
    if (!header?.startsWith('Bearer ')) {
        return reply.status(401).send({ error: 'Unauthorized', message: 'Missing Authorization header' })
    }

    try {
        const payload = await verifyAccessToken(header.slice(7))
        req.userId = payload.sub as string
        req.userEmail = payload.email
        req.userRole = payload.role as Role

        if (payload.role === 'ISSUER') {
            const p = await db.issuerProfile.findUnique({ where: { userId: req.userId }, select: { id: true } })
            if (p) req.issuerId = p.id
        }

        if (payload.role === 'VERIFIER') {
            const p = await db.verifierProfile.findUnique({ where: { userId: req.userId }, select: { id: true } })
            if (p) req.verifierId = p.id
        }
    } catch {
        return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or expired token' })
    }
}

// ── API KEY ───────────────────────────────────────────────────
export async function authenticateApiKey(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const header = req.headers.authorization
    if (!header?.startsWith('Bearer ')) {
        return reply.status(401).send({ error: 'Unauthorized', message: 'API key required' })
    }

    const key = header.slice(7)

    if (key.startsWith('vs_live_') || key.startsWith('vs_test_')) {
        const keyHash = sha256(key)
        const cached = await redis.get(keys.apiKey(keyHash))
        let apiKey: { id: string; verifierId: string; scopes: string[]; isActive: boolean } | null = null

        if (cached) {
            apiKey = JSON.parse(cached)
        } else {
            apiKey = await db.apiKey.findUnique({ where: { keyHash }, select: { id: true, verifierId: true, scopes: true, isActive: true } })
            if (apiKey) await redis.setex(keys.apiKey(keyHash), 60, JSON.stringify(apiKey))
        }

        if (!apiKey || !apiKey.isActive) {
            return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or revoked API key' })
        }

        db.apiKey.update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date(), lastUsedIp: req.ip, callCount: { increment: 1 } } }).catch(() => { })

        req.apiKeyId = apiKey.id
        req.verifierId = apiKey.verifierId
        req.userRole = 'VERIFIER'
    } else {
        return authenticate(req, reply)
    }
}

// ── OPTIONAL ──────────────────────────────────────────────────
export async function authenticateOptional(req: FastifyRequest, _reply: FastifyReply): Promise<void> {
    const header = req.headers.authorization
    if (!header?.startsWith('Bearer ')) return
    try {
        const payload = await verifyAccessToken(header.slice(7))
        req.userId = payload.sub as string
        req.userEmail = payload.email
        req.userRole = payload.role as Role
    } catch { /* silent */ }
}