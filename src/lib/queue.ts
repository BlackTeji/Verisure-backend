import { Queue } from 'bullmq'
import { redis } from './redis.js'

// ── NAMES ─────────────────────────────────────────────────────
export const QUEUES = {
    ANCHOR: 'verisure-anchor',
    EMAIL: 'verisure-email',
    BULK: 'verisure-bulk',
    WEBHOOK: 'verisure-webhook',
    EXPIRY: 'verisure-expiry',
} as const

// ── PAYLOADS ──────────────────────────────────────────────────
export interface AnchorJobData { credentialId: string; sha256Hash: string }
export interface EmailJobData {
    type: 'credential_issued' | 'email_verification' | 'password_reset' | 'credential_revoked' | 'expiry_reminder' | 'issuer_approved' | 'team_invite'
    to: string
    name?: string
    data: Record<string, unknown>
}
export interface BulkJobData { jobId: string; type: 'issuance' | 'verification'; fileKey: string; issuerId?: string; verifierId?: string }
export interface WebhookJobData { webhookId: string; event: string; payload: Record<string, unknown>; attempt?: number }

// ── QUEUES ────────────────────────────────────────────────────
const conn = redis

export const anchorQueue = new Queue<AnchorJobData, any, string>(QUEUES.ANCHOR, { connection: conn, defaultJobOptions: { attempts: 3, backoff: { type: 'exponential', delay: 2000 }, removeOnComplete: { count: 1000 }, removeOnFail: { count: 5000 } } })
export const emailQueue = new Queue<EmailJobData, any, string>(QUEUES.EMAIL, { connection: conn, defaultJobOptions: { attempts: 3, backoff: { type: 'exponential', delay: 1000 }, removeOnComplete: { count: 500 }, removeOnFail: { count: 1000 } } })
export const bulkQueue = new Queue<BulkJobData, any, string>(QUEUES.BULK, { connection: conn, defaultJobOptions: { attempts: 1, removeOnComplete: { count: 200 }, removeOnFail: { count: 500 } } })
export const webhookQueue = new Queue<WebhookJobData, any, string>(QUEUES.WEBHOOK, { connection: conn, defaultJobOptions: { attempts: 5, backoff: { type: 'exponential', delay: 5000 }, removeOnComplete: { count: 2000 }, removeOnFail: { count: 2000 } } })

// ── HEALTH ────────────────────────────────────────────────────
export async function getQueueHealth() {
    const [a, e, b, w] = await Promise.all([anchorQueue.getJobCounts(), emailQueue.getJobCounts(), bulkQueue.getJobCounts(), webhookQueue.getJobCounts()])
    return { anchor: a, email: e, bulk: b, webhook: w }
}