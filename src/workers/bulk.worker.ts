import { Worker } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { db } from '../lib/db.js'
import { anchorQueue, emailQueue, QUEUES } from '../lib/queue.js'
import { generateCredentialId, hashCredential } from '../lib/crypto.js'
import { parseStrictIsoDate } from '../lib/dates.js'
import { env } from '../config/env.js'
import type { BulkJobData } from '../lib/queue.js'

logger.info('bulk-worker: starting')

const worker = new Worker<BulkJobData>(
    QUEUES.BULK,
    async job => {
        const { jobId, type, fileKey, issuerId, verifierId } = job.data

        await db.bulkJob.update({ where: { id: jobId }, data: { status: 'PROCESSING', startedAt: new Date() } })

        if (type === 'issuance') await runIssuance(job, jobId, fileKey, issuerId!)
        else if (type === 'verification') await runVerification(job, jobId, fileKey, verifierId!)
    },
    { connection: redis, concurrency: 2, lockDuration: 600_000 }
)

// ── ISSUANCE ──────────────────────────────────────────────────

async function runIssuance(job: any, jobId: string, fileKey: string, issuerId: string) {
    let rows: any[]
    try { rows = JSON.parse(fileKey) } catch {
        await db.bulkJob.update({ where: { id: jobId }, data: { status: 'FAILED', completedAt: new Date(), errorLog: { error: 'Invalid JSON' } } })
        throw new Error('Invalid bulk payload')
    }

    const issuer = await db.issuerProfile.findUnique({ where: { id: issuerId }, select: { institutionName: true } })
    const BATCH = 50
    let succeeded = 0
    let failed = 0
    const errors: any[] = []

    for (let i = 0; i < rows.length; i += BATCH) {
        for (const [bi, row] of rows.slice(i, i + BATCH).entries()) {
            const idx = i + bi
            try {
                if (!row.holderName || !row.holderEmail || !row.credentialType || !row.issueDate)
                    throw new Error('Missing required fields')
                const email = String(row.holderEmail).toLowerCase().trim()
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
                    throw new Error(`Invalid email: ${email}`)
                
                const issueDateObj = parseStrictIsoDate(String(row.issueDate), 'issueDate')
                const expiryDateObj = row.expiryDate ? parseStrictIsoDate(String(row.expiryDate), 'expiryDate') : null

                const id = generateCredentialId()
                const sha256Hash = hashCredential({
                    id, issuerId,
                    holderName: String(row.holderName).trim(),
                    holderEmail: email,
                    credentialType: String(row.credentialType).trim(),
                    field: row.field ? String(row.field).trim() : null,
                    issueDate: issueDateObj.toISOString(),
                    expiryDate: expiryDateObj ? expiryDateObj.toISOString() : null,
                    notes: row.notes ? String(row.notes).trim() : null,
                })

                await db.credential.create({
                    data: {
                        id, issuerId,
                        holderName: String(row.holderName).trim(),
                        holderEmail: email,
                        credentialType: String(row.credentialType).trim(),
                        field: row.field ? String(row.field).trim() : null,
                        notes: row.notes ? String(row.notes).trim() : null,
                        issueDate: issueDateObj,
                        expiryDate: expiryDateObj,
                        sha256Hash,
                        status: 'ACTIVE',
                    },
                })

                await anchorQueue.add('anchor-bulk', { credentialId: id, sha256Hash }, { delay: idx * 200 })

                await emailQueue.add(`bulk-notify-${id}`, {
                    type: 'credential_issued',
                    to: email,
                    data: {
                        holderName: String(row.holderName).trim(),
                        credentialType: String(row.credentialType).trim(),
                        issuerName: issuer?.institutionName ?? '',
                        credentialId: id,
                        verifyUrl: `${env.FRONTEND_URL}/pages/verify.html?credential_id=${id}`,
                    },
                })

                succeeded++
            } catch (err) {
                failed++
                errors.push({ row: idx + 1, email: row.holderEmail ?? 'unknown', error: err instanceof Error ? err.message : String(err) })
                logger.warn({ jobId, row: idx + 1, err }, 'bulk-worker: row failed')
            }

            if (idx % 50 === 0) {
                await job.updateProgress(Math.floor((idx / rows.length) * 90))
                await db.bulkJob.update({ where: { id: jobId }, data: { processedRows: idx + 1, succeededRows: succeeded, failedRows: failed } })
            }
        }
    }

    const finalStatus = failed === 0 ? 'COMPLETED' : succeeded > 0 ? 'PARTIAL' : 'FAILED'
    await db.bulkJob.update({
        where: { id: jobId },
        data: { status: finalStatus, processedRows: rows.length, succeededRows: succeeded, failedRows: failed, completedAt: new Date(), errorLog: errors.length > 0 ? errors : undefined },
    })
    await job.updateProgress(100)

    const issuerUser = await db.issuerProfile.findUnique({
        where: { id: issuerId },
        include: { user: { select: { email: true } } },
    })
    if (issuerUser?.user.email) {
        await emailQueue.add('bulk-complete', {
            type: 'bulk_complete',
            to: issuerUser.user.email,
            data: {
                institutionName: issuer?.institutionName ?? '',
                jobId,
                totalRows: rows.length,
                succeeded,
                failed,
                status: finalStatus,
                dashboardUrl: `${env.FRONTEND_URL}/pages/dashboard-issuer.html`,
            },
        })
    }

    logger.info({ jobId, succeeded, failed, finalStatus }, 'bulk-worker: issuance done')
}

// ── VERIFICATION ──────────────────────────────────────────────

async function runVerification(job: any, jobId: string, fileKey: string, verifierId: string) {
    let rows: any[]
    try { rows = JSON.parse(fileKey) } catch {
        await db.bulkJob.update({ where: { id: jobId }, data: { status: 'FAILED', completedAt: new Date(), errorLog: { error: 'Invalid JSON' } } })
        throw new Error('Invalid bulk payload')
    }

    const BATCH = 100
    let succeeded = 0
    let failed = 0
    const results: any[] = []

    for (let i = 0; i < rows.length; i += BATCH) {
        const batch = rows.slice(i, i + BATCH)
        const batchIds = batch.map((r: any) => String(r.credential_id ?? r.id ?? '')).filter(Boolean)

        const creds = await db.credential.findMany({
            where: { id: { in: batchIds } },
            include: { issuer: { select: { institutionName: true, status: true } } },
        })
        const credMap = new Map(creds.map(c => [c.id, c]))

        for (const [bi, row] of batch.entries()) {
            const idx = i + bi
            const credId = String(row.credential_id ?? row.id ?? '').trim()

            if (!credId) {
                failed++
                results.push({ row: idx + 1, credential_id: credId, status: 'error', hash_valid: false, error: 'Missing credential_id' })
                continue
            }

            const c = credMap.get(credId)
            if (!c) {
                failed++
                results.push({ row: idx + 1, credential_id: credId, status: 'not_found', hash_valid: false })
                await db.verificationLog.create({
                    data: { credentialId: credId, verifierId, method: 'BULK_CSV', result: 'ACTIVE', hashValid: false, issuerApproved: false, ipAddress: 'bulk' },
                }).catch(() => { })
                continue
            }

            const recomputed = hashCredential({
                id: c.id, issuerId: c.issuerId,
                holderName: c.holderName, holderEmail: c.holderEmail,
                credentialType: c.credentialType, field: c.field,
                issueDate: c.issueDate.toISOString(),
                expiryDate: c.expiryDate?.toISOString() ?? null,
                notes: c.notes,
            })
            const hashValid = recomputed === c.sha256Hash
            const issuerApproved = c.issuer.status === 'APPROVED'
            const isExpired = c.expiryDate && c.expiryDate < new Date()
            const status = isExpired && c.status === 'ACTIVE' ? 'EXPIRED' : c.status

            await db.verificationLog.create({
                data: { credentialId: c.id, verifierId, method: 'BULK_CSV', result: status as any, hashValid, issuerApproved, ipAddress: 'bulk' },
            }).catch(() => { })

            succeeded++
            results.push({ row: idx + 1, credential_id: credId, status: status.toLowerCase(), hash_valid: hashValid, issuer_name: c.issuer.institutionName })
        }

        await job.updateProgress(Math.min(Math.floor(((i + BATCH) / rows.length) * 90), 90))
        await db.bulkJob.update({ where: { id: jobId }, data: { processedRows: i + batch.length, succeededRows: succeeded, failedRows: failed } })
    }

    const resultPayload = JSON.stringify(results)
    const INLINE_LIMIT = 500_000

    const resultFileUrl = resultPayload.length <= INLINE_LIMIT
        ? `data:application/json;base64,${Buffer.from(resultPayload).toString('base64')}`
        : null

    const finalStatus = failed === rows.length ? 'FAILED' : 'COMPLETED'
    await db.bulkJob.update({
        where: { id: jobId },
        data: { status: finalStatus, processedRows: rows.length, succeededRows: succeeded, failedRows: failed, completedAt: new Date(), ...(resultFileUrl ? { resultFileUrl } : {}) },
    })
    await job.updateProgress(100)

    logger.info({ jobId, succeeded, failed, finalStatus }, 'bulk-worker: verification done')
}

// ── EVENTS ────────────────────────────────────────────────────

worker.on('failed', async (job, err) => {
    logger.error({ jobId: job?.id, err }, 'bulk-worker: job failed')
    if (job?.data.jobId) {
        await db.bulkJob.update({
            where: { id: job.data.jobId },
            data: { status: 'FAILED', completedAt: new Date(), errorLog: { error: err.message } },
        }).catch(() => { })
    }
})

worker.on('error', err => logger.error({ err }, 'bulk-worker: error'))

process.on('SIGTERM', async () => {
    logger.info('bulk-worker: stopping')
    await worker.close()
    process.exit(0)
})