import { Resend } from 'resend'
import { env } from '../config/env.js'
import { logger } from './logger.js'

const resend = new Resend(env.RESEND_API_KEY)

// ── SEND ──────────────────────────────────────────────────────
interface SendEmailOptions {
    to: string
    subject: string
    html: string
    text: string
}

export async function sendEmail({ to, subject, html, text }: SendEmailOptions): Promise<void> {
    const { data, error } = await resend.emails.send({
        from: env.EMAIL_FROM,
        to,
        subject,
        html,
        text,
    })

    if (error) {
        logger.error({ error, to, subject }, 'mailer: resend error')
        throw new Error(`Email send failed: ${error.message}`)
    }

    logger.info({ id: data?.id, to, subject }, 'mailer: sent')
}

// ── BASE TEMPLATE ─────────────────────────────────────────────
const wrap = (body: string) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#F0EDE6;margin:0;padding:32px 16px;-webkit-font-smoothing:antialiased}
  .wrap{max-width:520px;margin:0 auto}
  .card{background:#ffffff;border-radius:12px;padding:40px;border:1px solid #E4E0D8}
  .logo{font-size:20px;color:#0E0E0C;margin-bottom:32px;letter-spacing:-0.3px}
  .logo em{font-style:italic;color:#D94010}
  h1{font-size:21px;color:#0E0E0C;margin:0 0 10px;letter-spacing:-0.3px;font-weight:600}
  p{font-size:14px;color:#6B6860;line-height:1.7;margin:0 0 16px}
  strong{color:#0E0E0C;font-weight:600}
  .btn{display:inline-block;background:#D94010;color:#ffffff !important;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;margin:8px 0;letter-spacing:0.1px}
  .mono{font-family:'SF Mono',Monaco,monospace;font-size:12px;background:#F5F3EE;border:1px solid #E4E0D8;border-radius:6px;padding:12px 16px;word-break:break-all;color:#4A4640;margin:8px 0;letter-spacing:0.5px}
  .divider{border:none;border-top:1px solid #E4E0D8;margin:28px 0}
  .foot{text-align:center;margin-top:24px;font-size:12px;color:#A8A49C;line-height:1.6}
  .foot a{color:#D94010;text-decoration:none}
  .alert-box{background:#FFF8F6;border:1px solid #F5C4B8;border-radius:8px;padding:16px;margin:16px 0}
  .alert-box p{margin:0;color:#7A3020}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="logo">Veri<em>Sure</em></div>
      ${body}
      <hr class="divider">
      <div class="foot">
        VeriSure · Dabar Systems Ltd · Lagos, Nigeria<br>
        <a href="https://verisure.ng">verisure.ng</a>
      </div>
    </div>
  </div>
</body>
</html>`

// ── TEMPLATES ─────────────────────────────────────────────────
export const templates = {

    credentialIssued: (d: {
        holderName: string
        credentialType: string
        issuerName: string
        credentialId: string
        verifyUrl: string
    }) => ({
        subject: `Your ${d.credentialType} from ${d.issuerName} is ready`,
        html: wrap(`
            <h1>Your credential is ready.</h1>
            <p>Hi ${d.holderName},</p>
            <p><strong>${d.issuerName}</strong> has issued you a verified credential on VeriSure. It is cryptographically secured and independently verifiable.</p>
            <p><strong>Credential type:</strong> ${d.credentialType}<br>
            <strong>Issued by:</strong> ${d.issuerName}</p>
            <p class="mono">${d.credentialId}</p>
            <a href="${d.verifyUrl}" class="btn">View your credential →</a>
            <p style="margin-top:20px;font-size:13px">Anyone can verify this credential at any time using the link above or by scanning the QR code on your certificate.</p>
        `),
        text: `Your ${d.credentialType} from ${d.issuerName} is ready on VeriSure.\n\nCredential ID: ${d.credentialId}\n\nVerify: ${d.verifyUrl}`,
    }),

    emailVerification: (d: { name: string; verifyUrl: string }) => ({
        subject: 'Verify your VeriSure email address',
        html: wrap(`
            <h1>Verify your email.</h1>
            <p>Hi ${d.name},</p>
            <p>Click the button below to verify your email address and activate your VeriSure account. This link expires in 24 hours.</p>
            <a href="${d.verifyUrl}" class="btn">Verify email address →</a>
            <p style="margin-top:20px;font-size:13px;color:#A8A49C">If you did not create a VeriSure account, you can safely ignore this email.</p>
        `),
        text: `Verify your VeriSure email address: ${d.verifyUrl}\n\nThis link expires in 24 hours.`,
    }),

    passwordReset: (d: { name: string; resetUrl: string }) => ({
        subject: 'Reset your VeriSure password',
        html: wrap(`
            <h1>Reset your password.</h1>
            <p>Hi ${d.name},</p>
            <p>Click below to set a new password for your VeriSure account. This link expires in 1 hour.</p>
            <a href="${d.resetUrl}" class="btn">Reset password →</a>
            <p style="margin-top:20px;font-size:13px;color:#A8A49C">If you did not request a password reset, ignore this email. Your password has not changed.</p>
        `),
        text: `Reset your VeriSure password: ${d.resetUrl}\n\nThis link expires in 1 hour. If you did not request this, ignore this email.`,
    }),

    credentialRevoked: (d: {
        holderName: string
        credentialType: string
        issuerName: string
        reason: string
    }) => ({
        subject: `Your ${d.credentialType} credential has been revoked`,
        html: wrap(`
            <h1>Credential revoked.</h1>
            <p>Hi ${d.holderName},</p>
            <p>Your <strong>${d.credentialType}</strong> issued by <strong>${d.issuerName}</strong> has been revoked.</p>
            <p><strong>Reason:</strong> ${d.reason}</p>
            <p style="font-size:13px;color:#A8A49C">The blockchain record of your credential's original issuance remains permanent and immutable. If you believe this revocation was made in error, contact ${d.issuerName} directly.</p>
        `),
        text: `Your ${d.credentialType} from ${d.issuerName} has been revoked.\n\nReason: ${d.reason}\n\nContact ${d.issuerName} if you believe this is an error.`,
    }),

    expiryReminder: (d: {
        holderName: string
        credentialType: string
        issuerName: string
        expiryDate: string
        daysRemaining: number
    }) => ({
        subject: `Your ${d.credentialType} expires in ${d.daysRemaining} days`,
        html: wrap(`
            <h1>Credential expiry reminder.</h1>
            <p>Hi ${d.holderName},</p>
            <p>Your <strong>${d.credentialType}</strong> from <strong>${d.issuerName}</strong> expires on <strong>${d.expiryDate}</strong> — ${d.daysRemaining} days from today.</p>
            <p>Contact ${d.issuerName} to renew your credential before it expires.</p>
        `),
        text: `Your ${d.credentialType} from ${d.issuerName} expires on ${d.expiryDate} (${d.daysRemaining} days). Contact your issuer to renew.`,
    }),

    issuerApproved: (d: {
        contactName: string
        institutionName: string
        dashboardUrl: string
    }) => ({
        subject: `${d.institutionName} is approved on VeriSure`,
        html: wrap(`
            <h1>Your institution is approved.</h1>
            <p>Hi ${d.contactName},</p>
            <p><strong>${d.institutionName}</strong> has been approved on VeriSure. You can now issue tamper-proof credentials to your members and graduates.</p>
            <a href="${d.dashboardUrl}" class="btn">Go to issuer dashboard →</a>
            <p style="margin-top:20px;font-size:13px">Before issuing, enable two-factor authentication on your account — it is required before the first credential can be issued.</p>
        `),
        text: `${d.institutionName} is approved on VeriSure. Go to your dashboard: ${d.dashboardUrl}\n\nEnable two-factor authentication before issuing.`,
    }),

    // ── New: admin notification when issuer submits for review ─
    adminNotification: (d: {
        institutionName: string
        issuerId: string
        dashboardUrl: string
    }) => ({
        subject: `New issuer application: ${d.institutionName}`,
        html: wrap(`
            <h1>New application for review.</h1>
            <p><strong>${d.institutionName}</strong> has submitted their onboarding application and is awaiting admin review.</p>
            <p><strong>Issuer ID:</strong> <span class="mono" style="display:inline;padding:2px 6px">${d.issuerId}</span></p>
            <a href="${d.dashboardUrl}" class="btn">Review in admin dashboard →</a>
            <p style="font-size:13px;color:#A8A49C">Target review SLA: 2 business days.</p>
        `),
        text: `New issuer application from ${d.institutionName} (ID: ${d.issuerId}).\n\nReview at: ${d.dashboardUrl}\n\nTarget SLA: 2 business days.`,
    }),

    // ── New: new device / new IP login alert ──────────────────
    newDeviceAlert: (d: {
        name: string
        email: string
        ipAddress: string
        userAgent: string
        loginTime: string
        accountUrl: string
    }) => ({
        subject: 'New sign-in to your VeriSure account',
        html: wrap(`
            <h1>New sign-in detected.</h1>
            <p>Hi ${d.name},</p>
            <p>We detected a sign-in to your VeriSure account from a new location or device.</p>
            <div class="alert-box">
                <p><strong>Time:</strong> ${d.loginTime}<br>
                <strong>IP address:</strong> ${d.ipAddress}<br>
                <strong>Device:</strong> ${d.userAgent}</p>
            </div>
            <p>If this was you, no action is needed.</p>
            <p>If you did not sign in, your account may be compromised. Change your password immediately and enable two-factor authentication.</p>
            <a href="${d.accountUrl}" class="btn">Secure my account →</a>
        `),
        text: `New sign-in to your VeriSure account.\n\nTime: ${d.loginTime}\nIP: ${d.ipAddress}\nDevice: ${d.userAgent}\n\nIf this wasn't you, change your password immediately: ${d.accountUrl}`,
    }),
}