import type { FastifyRequest, FastifyReply } from 'fastify'
import { redis, keys } from '../lib/redis.js'
import { db } from '../lib/db.js'
import type { Role } from '@prisma/client'

// ── RBAC ──────────────────────────────────────────────────────
export function requireRole(...roles: Role[]) {
    return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
        if (!req.userRole || !roles.includes(req.userRole)) {
            return reply.status(403).send({ error: 'Forbidden', message: `Requires: ${roles.join(', ')}` })
        }
    }
}

export const requireHolder = requireRole('HOLDER')
export const requireIssuer = requireRole('ISSUER')
export const requireVerifier = requireRole('VERIFIER')
export const requireAdmin = requireRole('ADMIN')
export const requireIssuerOrAdmin = requireRole('ISSUER', 'ADMIN')
export const requireVerifierOrAdmin = requireRole('VERIFIER', 'ADMIN')

// ── APPROVED ISSUER ───────────────────────────────────────────
export async function requireApprovedIssuer(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (!req.issuerId) return reply.status(403).send({ error: 'Forbidden', message: 'Issuer profile not found' })

    const cacheKey = keys.issuerStatus(req.issuerId)
    let status = await redis.get(cacheKey)

    if (!status) {
        const p = await db.issuerProfile.findUnique({ where: { id: req.issuerId }, select: { status: true } })
        status = p?.status ?? 'UNKNOWN'
        await redis.setex(cacheKey, 300, status)
    }

    if (status !== 'APPROVED') {
        const msg: Record<string, string> = {
            PENDING: 'Your application is pending review.',
            SUSPENDED: 'Your account is suspended. Contact support.',
            FROZEN: 'Your account is temporarily frozen. Contact support.',
        }
        return reply.status(403).send({ error: 'Forbidden', message: msg[status] ?? 'Account not active' })
    }
}

// ── API KEY SCOPE ─────────────────────────────────────────────
export function requireScope(scope: string) {
    return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
        if (!req.apiKeyId) return
        const k = await db.apiKey.findUnique({ where: { id: req.apiKeyId }, select: { scopes: true } })
        if (!k?.scopes.includes(scope)) {
            return reply.status(403).send({ error: 'Forbidden', message: `Requires '${scope}' scope` })
        }
    }
}