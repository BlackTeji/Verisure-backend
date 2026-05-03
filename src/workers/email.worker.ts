import { Worker } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { sendEmail, templates } from '../lib/mailer.js'
import type { EmailJobData } from '../lib/queue.js'

logger.info('email-worker: starting')

const worker = new Worker<EmailJobData>(
    'vrs:email',
    async job => {
        const { type, to, name, data } = job.data
        logger.info({ type, to, jobId: job.id }, 'email-worker: processing')

        let email: { subject: string; html: string; text: string }

        switch (type) {
            case 'credential_issued': email = templates.credentialIssued(data as any); break
            case 'email_verification': email = templates.emailVerification({ name: name ?? 'there', verifyUrl: data['verifyUrl'] as string }); break
            case 'password_reset': email = templates.passwordReset({ name: name ?? 'there', resetUrl: data['resetUrl'] as string }); break
            case 'credential_revoked': email = templates.credentialRevoked(data as any); break
            case 'expiry_reminder': email = templates.expiryReminder(data as any); break
            case 'issuer_approved': email = templates.issuerApproved(data as any); break
            case 'team_invite': email = templates.emailVerification({ name: name ?? 'there', verifyUrl: data['verifyUrl'] as string }); break
            default:
                logger.warn({ type }, 'email-worker: unknown type')
                return
        }

        await sendEmail({ to, ...email })
    },
    { connection: redis, concurrency: 10, limiter: { max: 30, duration: 1000 } }
)

worker.on('failed', (job, err) => logger.error({ jobId: job?.id, err }, 'email-worker: job failed'))

process.on('SIGTERM', async () => { logger.info('email-worker: stopping'); await worker.close(); process.exit(0) })