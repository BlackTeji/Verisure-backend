import { Worker } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { anchorHash, checkAnchorWalletBalance, pingContract } from '../lib/blockchain.js'
import { db } from '../lib/db.js'
import type { AnchorJobData } from '../lib/queue.js'

// ── STARTUP ───────────────────────────────────────────────────
logger.info('anchor-worker: starting')

// Confirm RPC + contract is reachable before accepting any jobs.
// Logs a warning but does NOT exit — jobs will fail individually
// and BullMQ will retry. This is intentional: a cold-start RPC
// timeout shouldn't prevent the worker from processing later.
pingContract().then(({ ok, network, contract }) => {
    if (ok) logger.info({ network, contract }, 'anchor-worker: contract reachable')
    else logger.error({ network, contract }, 'anchor-worker: contract NOT reachable — check POLYGON_RPC_URL and POLYGON_ANCHOR_CONTRACT')
}).catch(err => logger.error({ err }, 'anchor-worker: contract ping failed'))

// Check wallet balance. Low balance = credentials will fail to anchor.
// Alert loudly but do not exit.
checkAnchorWalletBalance().then(b => {
    if (!b.isSufficient) {
        logger.error({ balance: b.balanceMatic, address: b.address },
            'anchor-worker: WALLET BALANCE LOW — top up MATIC or anchoring will fail')
    } else {
        logger.info({ balance: b.balanceMatic, address: b.address }, 'anchor-worker: wallet balance ok')
    }
}).catch(err => logger.error({ err }, 'anchor-worker: wallet balance check failed'))

// ── WORKER ────────────────────────────────────────────────────
// concurrency: 5 — process up to 5 credentials in parallel.
// limiter: 10 anchor calls/sec max — respects Polygon RPC rate limits
//   on free Alchemy/QuickNode tiers (300 req/sec — well within budget).
// BullMQ handles retries: 3 attempts, exponential backoff (see queue.ts).
// Do NOT add retry logic inside the job handler — it doubles up with BullMQ.

const worker = new Worker<AnchorJobData>(
    'vrs:anchor',
    async job => {
        const { credentialId, sha256Hash } = job.data

        logger.info({ credentialId, jobId: job.id, attempt: job.attemptsMade + 1 }, 'anchor-worker: processing')
        await job.updateProgress(5)

        // ── Guard: credential must exist ──────────────────────
        const cred = await db.credential.findUnique({
            where: { id: credentialId },
            select: { id: true, txHash: true, anchoredAt: true, status: true },
        })

        if (!cred) {
            // Credential deleted between issuance and anchoring — discard job silently.
            logger.warn({ credentialId }, 'anchor-worker: credential not found — discarding job')
            return
        }

        // ── Guard: already anchored ───────────────────────────
        if (cred.txHash && cred.anchoredAt) {
            logger.info({ credentialId, txHash: cred.txHash }, 'anchor-worker: already anchored — skipping')
            return
        }

        // ── Guard: revoked credentials are not anchored ───────
        if (cred.status === 'REVOKED') {
            logger.info({ credentialId }, 'anchor-worker: credential revoked before anchoring — discarding')
            return
        }

        await job.updateProgress(10)

        // ── Anchor ────────────────────────────────────────────

        const result = await anchorHash(credentialId, sha256Hash)

        await job.updateProgress(100)

        logger.info({
            credentialId,
            txHash: result.txHash,
            blockNumber: result.blockNumber,
            gasUsed: result.gasUsed,
            network: result.network,
        }, 'anchor-worker: done')
    },
    {
        connection: redis,
        concurrency: 5,
        limiter: { max: 10, duration: 1000 },
    }
)

// ── EVENTS ────────────────────────────────────────────────────
worker.on('completed', job => {
    logger.info({ jobId: job.id, credentialId: job.data.credentialId }, 'anchor-worker: job completed')
})

worker.on('failed', (job, err) => {
    logger.error({
        jobId: job?.id,
        credentialId: job?.data?.credentialId,
        attempt: job?.attemptsMade,
        err: err.message,
    }, 'anchor-worker: job failed')

    if (job && job.attemptsMade >= 3) {
        db.credential.update({
            where: { id: job.data.credentialId },
            data: { blockchainNetwork: 'anchor-failed' },
        }).catch(dbErr => logger.error({ dbErr }, 'anchor-worker: failed to mark anchor failure'))
    }
})

worker.on('error', err => {
    logger.error({ err }, 'anchor-worker: worker-level error')
})

// ── GRACEFUL SHUTDOWN ─────────────────────────────────────────
async function shutdown(signal: string) {
    logger.info({ signal }, 'anchor-worker: shutting down')
    await worker.close()
    logger.info('anchor-worker: stopped cleanly')
    process.exit(0)
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))