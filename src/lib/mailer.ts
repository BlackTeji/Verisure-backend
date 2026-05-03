import nodemailer, { type Transporter } from 'nodemailer'
import { env } from '../config/env.js'
import { logger } from './logger.js'

let _transport: Transporter | null = null

function transport(): Transporter {
    if (!_transport) {
        _transport = nodemailer.createTransport({
            host: env.SMTP_HOST, port: env.SMTP_PORT, secure: env.SMTP_SECURE,
            auth: { user: env.SMTP_USER, pass: env.SMTP_PASSWORD },
            pool: true, maxConnections: 5,
        })
    }
    return _transport
}

export async function sendEmail(opts: { to: string; subject: string; html: string; text: string }): Promise<void> {
    try {
        await transport().sendMail({ from: env.EMAIL_FROM, replyTo: env.EMAIL_REPLY_TO, ...opts })
        logger.info({ to: opts.to, subject: opts.subject }, 'email: sent')
    } catch (err) {
        logger.error({ to: opts.to, subject: opts.subject, err }, 'email: failed')
        throw err
    }
}

// ── TEMPLATES ─────────────────────────────────────────────────
const wrap = (body: string) => `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#F5F4F0;margin:0;padding:32px 16px}
.c{background:#fff;border-radius:12px;max-width:520px;margin:0 auto;padding:40px;border:1px solid #E8E5E0}
.logo{font-family:Georgia,serif;font-size:22px;color:#0E0E0C;margin-bottom:32px}.logo em{font-style:italic;color:#8B2500}
h1{font-family:Georgia,serif;font-size:22px;color:#0E0E0C;margin:0 0 12px}
p{font-size:14px;color:#7A7870;line-height:1.7;margin:0 0 16px}
.btn{display:inline-block;background:#8B2500;color:#F7EDE8;padding:12px 28px;border-radius:6px;text-decoration:none;font-size:14px;font-weight:600;margin:8px 0}
.mono{font-family:monospace;font-size:12px;background:#F5F4F0;border:1px solid #E8E5E0;border-radius:6px;padding:12px 16px;word-break:break-all;color:#4A4840;margin:8px 0}
.foot{text-align:center;margin-top:32px;font-size:12px;color:#A8A49C}
hr{border:none;border-top:1px solid #E8E5E0;margin:24px 0}
</style></head><body><div class="c"><div class="logo">Veri<em>Sure</em></div>${body}<hr><div class="foot">VeriSure Technologies Ltd · Lagos, Nigeria<br><a href="https://verisure.ng" style="color:#8B2500">verisure.ng</a></div></div></body></html>`

export const templates = {
    credentialIssued: (d: { holderName: string; credentialType: string; issuerName: string; credentialId: string; verifyUrl: string }) => ({
        subject: `Your ${d.credentialType} credential from ${d.issuerName} is ready`,
        html: wrap(`<h1>Your credential is ready.</h1><p>Hi ${d.holderName},</p><p><strong>${d.issuerName}</strong> has issued you a verified credential on VeriSure.</p><p><strong>Type:</strong> ${d.credentialType}</p><p class="mono">${d.credentialId}</p><a href="${d.verifyUrl}" class="btn">View credential →</a>`),
        text: `Your ${d.credentialType} from ${d.issuerName} is ready. ID: ${d.credentialId}. Verify: ${d.verifyUrl}`,
    }),

    emailVerification: (d: { name: string; verifyUrl: string }) => ({
        subject: 'Verify your VeriSure email address',
        html: wrap(`<h1>Verify your email.</h1><p>Hi ${d.name},</p><p>Click below to verify your email and activate your account. Expires in 24 hours.</p><a href="${d.verifyUrl}" class="btn">Verify email →</a>`),
        text: `Verify your VeriSure email: ${d.verifyUrl}`,
    }),

    passwordReset: (d: { name: string; resetUrl: string }) => ({
        subject: 'Reset your VeriSure password',
        html: wrap(`<h1>Reset your password.</h1><p>Hi ${d.name},</p><p>Click below to reset your password. Expires in 1 hour.</p><a href="${d.resetUrl}" class="btn">Reset password →</a><p>If you did not request this, ignore this email.</p>`),
        text: `Reset your VeriSure password: ${d.resetUrl}`,
    }),

    credentialRevoked: (d: { holderName: string; credentialType: string; issuerName: string; reason: string }) => ({
        subject: `Your ${d.credentialType} credential has been revoked`,
        html: wrap(`<h1>Credential revoked.</h1><p>Hi ${d.holderName},</p><p>Your <strong>${d.credentialType}</strong> from <strong>${d.issuerName}</strong> has been revoked.</p><p><strong>Reason:</strong> ${d.reason}</p>`),
        text: `Your ${d.credentialType} from ${d.issuerName} has been revoked. Reason: ${d.reason}`,
    }),

    expiryReminder: (d: { holderName: string; credentialType: string; issuerName: string; expiryDate: string; daysRemaining: number }) => ({
        subject: `Your ${d.credentialType} expires in ${d.daysRemaining} days`,
        html: wrap(`<h1>Credential expiry reminder.</h1><p>Hi ${d.holderName},</p><p>Your <strong>${d.credentialType}</strong> from <strong>${d.issuerName}</strong> expires on <strong>${d.expiryDate}</strong> — ${d.daysRemaining} days from today.</p>`),
        text: `Your ${d.credentialType} expires in ${d.daysRemaining} days (${d.expiryDate}).`,
    }),

    issuerApproved: (d: { contactName: string; institutionName: string; dashboardUrl: string }) => ({
        subject: `${d.institutionName} is approved on VeriSure`,
        html: wrap(`<h1>Your institution is approved.</h1><p>Hi ${d.contactName},</p><p><strong>${d.institutionName}</strong> has been approved. You can now issue credentials.</p><a href="${d.dashboardUrl}" class="btn">Go to dashboard →</a>`),
        text: `${d.institutionName} approved. Dashboard: ${d.dashboardUrl}`,
    }),
}