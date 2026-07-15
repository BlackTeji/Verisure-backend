import type { FastifyInstance } from 'fastify'
import { redis } from '../lib/redis.js'

const METRICS_KEY = 'metrics:api_latency'
const WINDOW_MS = 24 * 60 * 60 * 1000
const MAX_ENTRIES = 50000

export async function registerMetricsHook(app: FastifyInstance) {
    app.addHook('onResponse', async (req, reply) => {
        try {
            const now = Date.now()
            const entry = JSON.stringify({
                ts: now,
                durationMs: Math.round(reply.elapsedTime),
                status: reply.statusCode,
            })
            await redis.zadd(METRICS_KEY, now, entry)

            if (Math.random() < 0.01) {
                await redis.zremrangebyscore(METRICS_KEY, 0, now - WINDOW_MS)
                const count = await redis.zcard(METRICS_KEY)
                if (count > MAX_ENTRIES) {
                    await redis.zremrangebyrank(METRICS_KEY, 0, count - MAX_ENTRIES - 1)
                }
            }
        } catch (err) {
            app.log.warn({ err }, 'metrics: failed to record')
        }
    })
}