import { Worker } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { anchorHash, checkAnchorWalletBalance } from '../lib/blockchain.js'
import { db } from '../lib/db.js'
import type { AnchorJobData } from '../lib/queue.js'

logger.info('anchor-worker: starting')

checkAnchorWalletBalance().then(b => {
    if (!b.isSufficient) logger.error({ balance: b.balanceMatic, address: b.address }, 'anchor-worker: low balance')
    else logger.info({ balance: b.balanceMatic }, 'anchor-worker: balance ok')
}).catch(err => logger.error({ err }, 'anchor-worker: balance check failed'))

const worker = new Worker<AnchorJobData>(
    'vrs:anchor',
    async job => {
        const { credentialId, sha256Hash } = job.data
        logger.info({ credentialId, jobId: job.id }, 'anchor-worker: processing')

        const cred = await db.credential.findUnique({ where: { id: credentialId }, select: { id: true, txHash: true, anchoredAt: true } })
        if (!cred) { logger.warn({ credentialId }, 'anchor-worker: not found'); return }
        if (cred.txHash && cred.anchoredAt) { logger.info({ credentialId }, 'anchor-worker: already anchored'); return }

        await job.updateProgress(10)
        await anchorHash(credentialId, sha256Hash)
        await job.updateProgress(100)

        logger.info({ credentialId }, 'anchor-worker: done')
    },
    {
        connection: redis,
        concurrency: 5,
        limiter: { max: 10, duration: 1000 },
    }
)

worker.on('failed', (job, err) => logger.error({ jobId: job?.id, err }, 'anchor-worker: job failed'))
worker.on('error', err => logger.error({ err }, 'anchor-worker: error'))

process.on('SIGTERM', async () => { logger.info('anchor-worker: stopping'); await worker.close(); process.exit(0) })