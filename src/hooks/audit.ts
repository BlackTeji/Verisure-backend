import type { FastifyRequest } from 'fastify'
import { Prisma } from '@prisma/client'
import type { AuditAction } from '@prisma/client'
import { db } from '../lib/db.js'
import { logger } from '../lib/logger.js'

export interface AuditPayload {
    action: AuditAction
    req: FastifyRequest
    targetType?: string
    targetId?: string
    targetMeta?: Record<string, unknown>
    metadata?: Record<string, unknown>
}

export function audit(p: AuditPayload): void {
    db.auditLog.create({
        data: {
            action: p.action,
            actorId: p.req.userId ?? null,
            actorEmail: p.req.userEmail ?? null,
            actorRole: p.req.userRole ?? null,
            actorIp: p.req.ip,
            actorAgent: p.req.headers['user-agent']?.slice(0, 500) ?? null,
            targetType: p.targetType ?? null,
            targetId: p.targetId ?? null,
            targetMeta: (p.targetMeta as Prisma.InputJsonValue) ?? Prisma.JsonNull,
            metadata: (p.metadata as Prisma.InputJsonValue) ?? Prisma.JsonNull,
        },
    }).catch(err => logger.error({ err, action: p.action }, 'audit: write failed'))
}