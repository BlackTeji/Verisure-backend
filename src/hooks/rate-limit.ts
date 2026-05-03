import type { FastifyRequest, FastifyReply } from 'fastify'
import { redis, keys } from '../lib/redis.js'
import { db } from '../lib/db.js'
import { logger } from '../lib/logger.js'
import { env } from '../config/env.js'

// ── BLOCKED IP CHECK ──────────────────────────────────────────
export async function checkBlockedIp(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const blocked = await redis.get(keys.blockedIp(req.ip))
    if (blocked) {
        logger.warn({ ip: req.ip }, 'security: blocked ip')
        return reply.status(403).send({ error: 'Forbidden', message: 'Access denied' })
    }
}

// ── FRAUD TRACKING ────────────────────────────────────────────
export async function trackVerificationRate(req: FastifyRequest): Promise<void> {
    const ip = req.ip
    const countKey = keys.fraudCount(ip)
    const count = await redis.incr(countKey)
    const threshold = env.FRAUD_RATE_THRESHOLD

    if (count === 1) await redis.expire(countKey, env.FRAUD_RATE_WINDOW_SECONDS)

    if (count >= threshold) {
        logger.warn({ ip, count }, 'fraud: threshold exceeded')

        try {
            const existing = await db.fraudAlert.findFirst({ where: { ipAddress: ip, status: 'ACTIVE', type: 'rate_limit_breach' } })
            if (!existing) {
                await db.fraudAlert.create({
                    data: {
                        severity: count >= threshold * 3 ? 'CRITICAL' : 'HIGH',
                        status: 'ACTIVE',
                        type: 'rate_limit_breach',
                        description: `${count} requests in ${env.FRAUD_RATE_WINDOW_SECONDS}s window`,
                        ipAddress: ip,
                        metadata: { count, threshold, authenticated: !!req.userId } as any,
                    },
                })
            }
            if (env.FRAUD_AUTO_BLOCK && count >= threshold * 2) {
                await blockIp(ip, 'Auto: rate limit breach', 3600)
            }
        } catch (err) {
            logger.error({ err }, 'fraud: alert write failed')
        }
    }
}

// ── IP BLOCKING ───────────────────────────────────────────────
export async function blockIp(ip: string, reason: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
        await redis.setex(keys.blockedIp(ip), ttlSeconds, reason)
    } else {
        await redis.set(keys.blockedIp(ip), reason)
    }

    await db.blockedIp.upsert({
        where: { ipAddress: ip },
        update: { reason, expiresAt: ttlSeconds ? new Date(Date.now() + ttlSeconds * 1000) : null },
        create: { ipAddress: ip, reason, expiresAt: ttlSeconds ? new Date(Date.now() + ttlSeconds * 1000) : null },
    })

    logger.info({ ip, reason, ttlSeconds }, 'security: ip blocked')
}

export async function unblockIp(ip: string): Promise<void> {
    await redis.del(keys.blockedIp(ip))
    await db.blockedIp.delete({ where: { ipAddress: ip } }).catch(() => { })
    logger.info({ ip }, 'security: ip unblocked')
}

export async function syncBlockedIpsFromDb(): Promise<void> {
    const blocked = await db.blockedIp.findMany({
        where: { OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] },
    })

    const pipeline = redis.pipeline()
    for (const b of blocked) {
        if (b.expiresAt) {
            const ttl = Math.floor((b.expiresAt.getTime() - Date.now()) / 1000)
            if (ttl > 0) pipeline.setex(keys.blockedIp(b.ipAddress), ttl, b.reason)
        } else {
            pipeline.set(keys.blockedIp(b.ipAddress), b.reason)
        }
    }

    await pipeline.exec()
    logger.info({ count: blocked.length }, 'security: blocked ips loaded')
}