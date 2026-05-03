import { Worker, Queue } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { db } from '../lib/db.js'
import { emailQueue } from '../lib/queue.js'

logger.info('expiry-worker: starting')

const schedulerQueue = new Queue('verisure-expiry-scheduler', { connection: redis })

schedulerQueue.add('daily', {}, { repeat: { every: 86400000 } }).catch(err => logger.error({ err }, 'expiry-worker: schedule failed'))

const worker = new Worker('verisure-expiry-scheduler',
    async job => {
        logger.info({ jobId: job.id }, 'expiry-worker: running')

        const now = new Date()

        const expired = await db.credential.updateMany({ where: { status: 'ACTIVE', expiryDate: { lt: now } }, data: { status: 'EXPIRED' } })
        logger.info({ count: expired.count }, 'expiry-worker: marked expired')

        const in30 = new Date(now.getTime() + 30 * 86400000)
        const in60 = new Date(now.getTime() + 60 * 86400000)
        const in90 = new Date(now.getTime() + 90 * 86400000)

        let emailCount = 0

        for (const [targetDate, daysRemaining] of [[in90, 90], [in60, 60], [in30, 30]] as [Date, number][]) {
            const dayStart = new Date(targetDate); dayStart.setHours(0, 0, 0, 0)
            const dayEnd = new Date(targetDate); dayEnd.setHours(23, 59, 59, 999)

            const targets = await db.credential.findMany({
                where: { status: 'ACTIVE', expiryDate: { gte: dayStart, lte: dayEnd } },
                include: { issuer: { select: { institutionName: true } } },
            })

            for (const c of targets) {
                await emailQueue.add(`expiry-${daysRemaining}-${c.id}`, {
                    type: 'expiry_reminder',
                    to: c.holderEmail,
                    data: { holderName: c.holderName, credentialType: c.credentialType, issuerName: c.issuer.institutionName, expiryDate: c.expiryDate!.toLocaleDateString('en-NG', { day: 'numeric', month: 'long', year: 'numeric' }), daysRemaining },
                })
                emailCount++
            }
        }

        logger.info({ expired: expired.count, reminders: emailCount }, 'expiry-worker: done')
    },
    { connection: redis, concurrency: 1 }
)

worker.on('failed', (job, err) => logger.error({ jobId: job?.id, err }, 'expiry-worker: failed'))

process.on('SIGTERM', async () => { logger.info('expiry-worker: stopping'); await worker.close(); process.exit(0) })