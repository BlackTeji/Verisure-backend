import { Worker } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { db } from '../lib/db.js'
import { decrypt } from '../lib/crypto.js'
import { createHmac } from 'crypto'
import { QUEUES } from '../lib/queue.js'
import type { WebhookJobData } from '../lib/queue.js'

logger.info('webhook-worker: starting')

const worker = new Worker<WebhookJobData>(
    QUEUES.WEBHOOK,
    async job => {
        const { webhookId, event, payload } = job.data

        const webhook = await db.webhook.findUnique({
            where: { id: webhookId },
            select: { id: true, url: true, secretHash: true, isActive: true, events: true },
        })
        if (!webhook || !webhook.isActive) { logger.info({ webhookId }, 'webhook-worker: inactive'); return }
        if (!webhook.events.includes(event)) { logger.info({ webhookId, event }, 'webhook-worker: not subscribed'); return }

        const body = JSON.stringify({
            event,
            data: payload,
            timestamp: new Date().toISOString(),
            webhook_id: webhookId,
        })
        const sig = createHmac('sha256', decrypt(webhook.secretHash)).update(body).digest('hex')

        const start = Date.now()
        let statusCode: number | null = null
        let responseBody: string | null = null
        let success = false

        try {
            const res = await fetch(webhook.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-VeriSure-Event': event,
                    'X-VeriSure-Signature': `sha256=${sig}`,
                    'X-VeriSure-Delivery': job.id ?? 'unknown',
                    'User-Agent': 'VeriSure-Webhook/1.0',
                },
                body,
                signal: AbortSignal.timeout(15000),
            })
            statusCode = res.status
            responseBody = await res.text().catch(() => null)
            success = res.ok
        } catch (err) {
            logger.error({ webhookId, event, err }, 'webhook-worker: delivery failed')
        }

        const duration = Date.now() - start

        await db.webhookDelivery.create({
            data: {
                webhookId,
                event,
                payload: payload as object,
                statusCode,
                responseBody: responseBody?.slice(0, 500) ?? null,
                duration,
                attempt: (job.attemptsMade ?? 0) + 1,
                success,
            },
        })
        await db.webhook.update({
            where: { id: webhookId },
            data: { lastDeliveredAt: new Date(), failureCount: success ? 0 : { increment: 1 } },
        })

        if (!success) throw new Error(`Delivery failed with status ${statusCode}`)

        logger.info({ webhookId, event, statusCode, duration }, 'webhook-worker: delivered')
    },
    { connection: redis, concurrency: 20 }
)

worker.on('failed', (job, err) =>
    logger.error({ jobId: job?.id, webhookId: job?.data?.webhookId, event: job?.data?.event, err }, 'webhook-worker: failed'))

process.on('SIGTERM', async () => {
    logger.info('webhook-worker: stopping')
    await worker.close()
    process.exit(0)
})