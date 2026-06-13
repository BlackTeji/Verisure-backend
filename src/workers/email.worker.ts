import { Worker } from 'bullmq'
import { redis } from '../lib/redis.js'
import { logger } from '../lib/logger.js'
import { sendEmail, templates } from '../lib/mailer.js'
import { QUEUES } from '../lib/queue.js'
import type { EmailJobData } from '../lib/queue.js'

logger.info('email-worker: starting')

const worker = new Worker<EmailJobData>(
    QUEUES.EMAIL,
    async job => {
        const { type, to, name, data } = job.data
        logger.info({ type, to, jobId: job.id }, 'email-worker: processing')

        let email: { subject: string; html: string; text: string }

        switch (type) {
            case 'credential_issued':
                email = templates.credentialIssued(data as any)
                break
            case 'email_verification':
                email = templates.emailVerification({ name: name ?? 'there', verifyUrl: data['verifyUrl'] as string })
                break
            case 'password_reset':
                email = templates.passwordReset({ name: name ?? 'there', resetUrl: data['resetUrl'] as string })
                break
            case 'credential_revoked':
                email = templates.credentialRevoked(data as any)
                break
            case 'expiry_reminder':
                email = templates.expiryReminder(data as any)
                break
            case 'issuer_approved':
                email = templates.issuerApproved(data as any)
                break
            case 'team_invite':
                email = templates.emailVerification({ name: name ?? 'there', verifyUrl: data['verifyUrl'] as string })
                break
            case 'admin_notification':
                email = templates.adminNotification(data as any)
                break
            case 'new_device_alert':
                email = templates.newDeviceAlert(data as any)
                break
            case 'bulk_complete':
                email = templates.bulkComplete(data as any)
                break
            case 'share_grant_created':
                email = templates.shareGrantCreated(data as any)
                break
            default:
                logger.warn({ type }, 'email-worker: unknown email type — skipping')
                return
        }

        await sendEmail({ to, ...email })
    },
    { connection: redis, concurrency: 10, limiter: { max: 30, duration: 1000 } }
)

worker.on('failed', (job, err) =>
    logger.error({ jobId: job?.id, type: job?.data?.type, to: job?.data?.to, err }, 'email-worker: job failed'))

process.on('SIGTERM', async () => {
    logger.info('email-worker: stopping')
    await worker.close()
    process.exit(0)
})