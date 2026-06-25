import 'dotenv/config'
import { db } from '../lib/db.js'
import { anchorQueue } from '../lib/queue.js'
import { checkAnchorWalletBalance } from '../lib/blockchain.js'
import { logger } from '../lib/logger.js'

const MATIC_PER_ANCHOR = 0.002

const DELAY_BETWEEN_JOBS_MS = 2000

async function main() {
    const args = process.argv.slice(2)
    const dryRun = args.includes('--dry-run')
    const batchArg = args.find(a => a.startsWith('--batch'))
    const batchSize = batchArg ? parseInt(batchArg.split('=')[1] ?? batchArg.split(' ')[1] ?? '100', 10) : 100

    logger.info({ dryRun, batchSize }, 'backfill-anchors: starting')

    // -- Wallet balance check ------------------------------------------
    logger.info('backfill-anchors: checking wallet balance...')
    let walletBalance = 0
    let walletAddress = 'unknown'
    try {
        const b = await checkAnchorWalletBalance()
        walletBalance = parseFloat(b.balanceMatic)
        walletAddress = b.address
        logger.info({ balance: b.balanceMatic, address: walletAddress, sufficient: b.isSufficient },
            'backfill-anchors: wallet balance')
    } catch (err) {
        logger.error({ err }, 'backfill-anchors: could not check wallet balance - proceeding with caution')
    }

    // -- Find credentials needing anchoring ---------------------------

    const [failedCount, neverAnchoredCount] = await Promise.all([
        db.credential.count({
            where: {
                txHash: null,
                blockchainNetwork: 'anchor-failed',
                status: { not: 'REVOKED' },
            },
        }),
        db.credential.count({
            where: {
                txHash: null,
                blockchainNetwork: null,
                status: { not: 'REVOKED' },
            },
        }),
    ])

    const totalToProcess = failedCount + neverAnchoredCount
    const estimatedCost = (totalToProcess * MATIC_PER_ANCHOR).toFixed(4)
    const estimatedHours = ((totalToProcess * DELAY_BETWEEN_JOBS_MS) / 3_600_000).toFixed(1)

    logger.info({
        failedCount,
        neverAnchoredCount,
        totalToProcess,
        estimatedCostMatic: estimatedCost,
        estimatedDurationHours: estimatedHours,
        currentWalletBalanceMatic: walletBalance.toFixed(4),
        walletAddress,
    }, 'backfill-anchors: credential counts')

    if (totalToProcess === 0) {
        logger.info('backfill-anchors: nothing to do - all credentials are anchored or revoked')
        process.exit(0)
    }

    const neededMatic = totalToProcess * MATIC_PER_ANCHOR
    if (walletBalance > 0 && walletBalance < neededMatic) {
        logger.warn({
            needed: neededMatic.toFixed(4),
            available: walletBalance.toFixed(4),
            shortfall: (neededMatic - walletBalance).toFixed(4),
        }, 'backfill-anchors: WARNING - wallet balance may be insufficient for full backfill')
        logger.warn('backfill-anchors: top up wallet before proceeding, or jobs will fail mid-way again')
    }

    if (dryRun) {
        logger.info('backfill-anchors: DRY RUN - no changes made. Remove --dry-run to proceed.')
        process.exit(0)
    }

    logger.info('backfill-anchors: resetting anchor-failed credentials...')
    const resetResult = await db.credential.updateMany({
        where: {
            txHash: null,
            blockchainNetwork: 'anchor-failed',
            status: { not: 'REVOKED' },
        },
        data: { blockchainNetwork: null },
    })
    logger.info({ count: resetResult.count }, 'backfill-anchors: reset anchor-failed credentials')

    let processed = 0
    let queued = 0
    let cursor: string | undefined = undefined

    logger.info({ batchSize, delayBetweenJobsMs: DELAY_BETWEEN_JOBS_MS }, 'backfill-anchors: queueing jobs...')

    while (true) {
        const batch = await db.credential.findMany({
            where: {
                txHash: null,
                blockchainNetwork: null,
                status: { not: 'REVOKED' },
            },
            select: { id: true, sha256Hash: true },
            orderBy: { createdAt: 'asc' },
            take: batchSize,
            ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        })

        if (batch.length === 0) break

        const jobs = batch.map((cred, idx) => ({
            name: 'anchor-backfill',
            data: { credentialId: cred.id, sha256Hash: cred.sha256Hash },
            opts: {
 
                delay: (queued + idx) * DELAY_BETWEEN_JOBS_MS,
                attempts: 3,
                backoff: { type: 'exponential' as const, delay: 5000 },
                jobId: `backfill-${cred.id}`,
                removeOnComplete: { count: 500 },
                removeOnFail: { count: 1000 },
            },
        }))

        await anchorQueue.addBulk(jobs)

        processed += batch.length
        queued += batch.length
        cursor = batch[batch.length - 1]?.id

        if (processed % 500 === 0 || batch.length < batchSize) {
            logger.info({ processed, total: totalToProcess, pct: Math.round((processed / totalToProcess) * 100) },
                'backfill-anchors: progress')
        }

        await new Promise(resolve => setTimeout(resolve, 100))
    }

    const firstJobDelay = 0
    const lastJobDelay = (queued - 1) * DELAY_BETWEEN_JOBS_MS
    const completionEstimate = new Date(Date.now() + lastJobDelay + 30_000).toISOString()

    logger.info({
        queued,
        firstJobFiresAt: 'immediately',
        lastJobFiresAt: `${(lastJobDelay / 3_600_000).toFixed(1)} hours from now`,
        estimatedFullCompletionAt: completionEstimate,
    }, 'backfill-anchors: all jobs queued successfully')

    logger.info('backfill-anchors: done. Monitor worker-anchor logs for progress.')

    await new Promise(resolve => setTimeout(resolve, 2000))
    process.exit(0)
}

main().catch(err => {
    logger.error({ err }, 'backfill-anchors: fatal error')
    process.exit(1)
})