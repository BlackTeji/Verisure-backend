import { redis } from './redis.js'

const METRICS_KEY = 'metrics:api_latency'
const WINDOW_MS = 24 * 60 * 60 * 1000

export interface ApiMetrics {
    p50Ms: number | null
    p95Ms: number | null
    p99Ms: number | null
    successRatePct: string
    successfulCalls24h: number
    sampleSize: number
}

export async function getApiMetrics(): Promise<ApiMetrics> {
    const since = Date.now() - WINDOW_MS
    const raw = await redis.zrangebyscore(METRICS_KEY, since, '+inf')

    if (!raw.length) {
        return { p50Ms: null, p95Ms: null, p99Ms: null, successRatePct: '—', successfulCalls24h: 0, sampleSize: 0 }
    }

    const entries = raw.map(r => JSON.parse(r) as { ts: number; durationMs: number; status: number })
    const durations = entries.map(e => e.durationMs).sort((a, b) => a - b)
    const successes = entries.filter(e => e.status < 500).length

    const pct = (p: number) => durations[Math.min(durations.length - 1, Math.floor((p / 100) * durations.length))] ?? null

    return {
        p50Ms: pct(50),
        p95Ms: pct(95),
        p99Ms: pct(99),
        successRatePct: ((successes / entries.length) * 100).toFixed(1) + '%',
        successfulCalls24h: successes,
        sampleSize: entries.length,
    }
}

export async function pingDatabase(db: { $queryRaw: (query: TemplateStringsArray) => Promise<unknown> }): Promise<boolean> {
    try {
        await db.$queryRaw`SELECT 1`
        return true
    } catch {
        return false
    }
}

export async function pingRedis(): Promise<boolean> {
    try {
        const res = await redis.ping()
        return res === 'PONG'
    } catch {
        return false
    }
}

export async function pingResend(apiKey: string | undefined): Promise<boolean> {
    if (!apiKey) return false
    try {
        const res = await fetch('https://api.resend.com/domains', {
            headers: { Authorization: `Bearer ${apiKey}` },
        })
        return res.status < 500
    } catch {
        return false
    }
}

export async function pingR2(endpoint: string | undefined): Promise<boolean> {
    if (!endpoint) return false
    try {
        const res = await fetch(endpoint, { method: 'HEAD', signal: AbortSignal.timeout(3000) })
        return res.status < 500
    } catch {
        return false
    }
}