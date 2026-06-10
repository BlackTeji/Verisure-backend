// ═══════════════════════════════════════════════════════════════════
// VeriSure — Expiry Worker (TRD-HIGH-004)
// ═══════════════════════════════════════════════════════════════════
// Runs HOURLY (TRD §5.5 — expired credentials must verify as expired
// promptly, not up to 24h late).
//
// Responsibilities:
//   1. Transition ACTIVE → EXPIRED for credentials past expiryDate
//   2. Notify each holder by email at moment of expiry
//   3. Dispatch credential.expired webhooks to verifiers who have
//      previously verified that credential (TRD §6.5.1)
//   4. Send 90/60/30-day renewal reminder emails (Redis-deduplicated —
//      the hourly cadence would otherwise send 24 duplicates per day)
//   5. Housekeeping: purge expired blocked-IP rows
// ═══════════════════════════════════════════════════════════════════

import { Worker, Queue } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { db } from '../lib/db.js'
import { emailQueue, webhookQueue, QUEUES } from '../lib/queue.js'

logger.info('expiry-worker: starting')

// ── SCHEDULER SETUP ─────────────────────────────────────────────────
// Hourly repeatable job. On startup, remove any stale repeatable jobs
// (e.g. the previous daily 86_400_000ms schedule) so only one cadence
// is ever registered.

const HOURLY_MS = 3_600_000

const schedulerQueue = new Queue(QUEUES.EXPIRY_SCHEDULER, { connection: redis })

async function ensureSchedule() {
    const existing = await schedulerQueue.getRepeatableJobs()
    for (const job of existing) {
        if (job.every !== String(HOURLY_MS)) {
            await schedulerQueue.removeRepeatableByKey(job.key)
            logger.info({ removed: job.key, every: job.every }, 'expiry-worker: removed stale repeatable schedule')
        }
    }
    await schedulerQueue.add('hourly', {}, { repeat: { every: HOURLY_MS } })
    logger.info({ everyMs: HOURLY_MS }, 'expiry-worker: hourly schedule registered')
}

ensureSchedule().catch(err => logger.error({ err }, 'expiry-worker: schedule setup failed'))

// ── REMINDER DEDUP ──────────────────────────────────────────────────
// Key per (credential, threshold). TTL 8 days covers clock drift and
// worker downtime without permanent state.

const reminderKey = (credentialId: string, days: number) =>
    `vrs:expiry-reminder:${credentialId}:${days}`

const REMINDER_KEY_TTL_SECONDS = 8 * 86_400

// ── WORKER ──────────────────────────────────────────────────────────

const worker = new Worker(
    QUEUES.EXPIRY_SCHEDULER,
    async job => {
        logger.info({ jobId: job.id }, 'expiry-worker: run starting')

        const now = new Date()

        // ════════════════════════════════════════════════════════════
        // 1. EXPIRE CREDENTIALS — per-credential so each holder gets
        //    an email and each watching verifier gets a webhook
        // ════════════════════════════════════════════════════════════

        const toExpire = await db.credential.findMany({
            where: { status: 'ACTIVE', expiryDate: { not: null, lt: now } },
            include: { issuer: { select: { institutionName: true } } },
            take: 1000, // safety cap per run; remainder picked up next hour
        })

        let expiredCount = 0

        for (const cred of toExpire) {
            try {
                // Status transition — guarded update so a concurrent
                // revocation between query and write is never overwritten
                const result = await db.credential.updateMany({
                    where: { id: cred.id, status: 'ACTIVE' },
                    data: { status: 'EXPIRED' },
                })
                if (result.count === 0) continue
                expiredCount++

                // Audit trail
                await db.auditLog.create({
                    data: {
                        action: 'CREDENTIAL_EXPIRED',
                        actorId: null,
                        actorEmail: 'system',
                        actorRole: 'SYSTEM',
                        actorIp: 'worker',
                        targetType: 'credential',
                        targetId: cred.id,
                        metadata: { expiryDate: cred.expiryDate?.toISOString() },
                    },
                }).catch(err => logger.error({ err, credentialId: cred.id }, 'expiry-worker: audit write failed'))

                // Holder notification email
                await emailQueue.add(`expired-${cred.id}`, {
                    type: 'expiry_reminder',
                    to: cred.holderEmail,
                    data: {
                        holderName: cred.holderName,
                        credentialType: cred.credentialType,
                        issuerName: cred.issuer.institutionName,
                        expiryDate: cred.expiryDate!.toLocaleDateString('en-NG', { day: 'numeric', month: 'long', year: 'numeric' }),
                        daysRemaining: 0,
                    },
                }).catch(err => logger.error({ err, credentialId: cred.id }, 'expiry-worker: email enqueue failed'))

                // credential.expired webhooks — verifiers who previously
                // verified this credential (TRD §6.5.1)
                const watchers = await db.verificationLog.findMany({
                    where: { credentialId: cred.id, verifierId: { not: null } },
                    select: { verifierId: true },
                    distinct: ['verifierId'],
                })

                for (const w of watchers) {
                    if (!w.verifierId) continue
                    const hooks = await db.webhook.findMany({
                        where: { verifierId: w.verifierId, isActive: true, events: { has: 'credential.expired' } },
                        select: { id: true },
                    })
                    for (const h of hooks) {
                        await webhookQueue.add('webhook', {
                            webhookId: h.id,
                            event: 'credential.expired',
                            payload: {
                                credentialId: cred.id,
                                credentialType: cred.credentialType,
                                expiryDate: cred.expiryDate?.toISOString(),
                                expiredAt: now.toISOString(),
                            },
                        }).catch(err => logger.error({ err, webhookId: h.id }, 'expiry-worker: webhook enqueue failed'))
                    }
                }
            } catch (err) {
                logger.error({ err, credentialId: cred.id }, 'expiry-worker: failed to process expiry')
            }
        }

        logger.info({ count: expiredCount }, 'expiry-worker: credentials expired')

        // ════════════════════════════════════════════════════════════
        // 2. RENEWAL REMINDERS — 90 / 60 / 30 days (TRD §5.5)
        //    Deduplicated via Redis so hourly runs send exactly once
        // ════════════════════════════════════════════════════════════

        const thresholds: [Date, number][] = [
            [new Date(now.getTime() + 90 * 86_400_000), 90],
            [new Date(now.getTime() + 60 * 86_400_000), 60],
            [new Date(now.getTime() + 30 * 86_400_000), 30],
        ]

        let reminderCount = 0

        for (const [targetDate, daysRemaining] of thresholds) {
            const dayStart = new Date(targetDate); dayStart.setHours(0, 0, 0, 0)
            const dayEnd = new Date(targetDate); dayEnd.setHours(23, 59, 59, 999)

            const targets = await db.credential.findMany({
                where: { status: 'ACTIVE', expiryDate: { gte: dayStart, lte: dayEnd } },
                include: { issuer: { select: { institutionName: true } } },
            })

            for (const c of targets) {
                // Dedup: skip if this (credential, threshold) reminder
                // was already sent in a previous hourly run
                const key = reminderKey(c.id, daysRemaining)
                const alreadySent = await redis.set(key, '1', 'EX', REMINDER_KEY_TTL_SECONDS, 'NX')
                if (alreadySent !== 'OK') continue

                await emailQueue.add(`expiry-${daysRemaining}-${c.id}`, {
                    type: 'expiry_reminder',
                    to: c.holderEmail,
                    data: {
                        holderName: c.holderName,
                        credentialType: c.credentialType,
                        issuerName: c.issuer.institutionName,
                        expiryDate: c.expiryDate!.toLocaleDateString('en-NG', { day: 'numeric', month: 'long', year: 'numeric' }),
                        daysRemaining,
                    },
                }).catch(async err => {
                    await redis.del(key).catch(() => { })
                    logger.error({ err, credentialId: c.id }, 'expiry-worker: reminder enqueue failed')
                })
                reminderCount++
            }
        }

        // ════════════════════════════════════════════════════════════
        // 3. HOUSEKEEPING — purge expired blocked-IP rows
        // ════════════════════════════════════════════════════════════

        const cleaned = await db.blockedIp.deleteMany({
            where: { expiresAt: { lt: now } },
        })

        logger.info(
            { expired: expiredCount, reminders: reminderCount, blockedIpsCleaned: cleaned.count },
            'expiry-worker: run complete',
        )
    },
    { connection: redis, concurrency: 1 }
)

// ── EVENTS ──────────────────────────────────────────────────────────

worker.on('failed', (job, err) =>
    logger.error({ jobId: job?.id, err }, 'expiry-worker: failed'))

worker.on('error', err =>
    logger.error({ err }, 'expiry-worker: worker-level error'))

// ── GRACEFUL SHUTDOWN ───────────────────────────────────────────────

async function shutdown(signal: string) {
    logger.info({ signal }, 'expiry-worker: stopping')
    await worker.close()
    await schedulerQueue.close()
    process.exit(0)
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))