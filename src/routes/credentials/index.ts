import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../../lib/db.js'
import { generateCredentialId, hashCredential } from '../../lib/crypto.js'
import { sha256 } from '../../lib/crypto.js'
import { anchorQueue, emailQueue, webhookQueue } from '../../lib/queue.js'
import { authenticate, authenticateApiKey, authenticateOptional } from '../../hooks/authenticate.js'
import { requireIssuer, requireApprovedIssuer, requireScope } from '../../hooks/authorize.js'
import { audit } from '../../hooks/audit.js'
import { trackVerificationRate } from '../../hooks/rate-limit.js'
import { verifyHashOnChain } from '../../lib/blockchain.js'
import { env } from '../../config/env.js'

// ── ISSUE ─────────────────────────────────────────────────────
export default async function credentialRoutes(app: FastifyInstance) {

    app.post('/', { preHandler: [authenticate, requireIssuer, requireApprovedIssuer] }, async (req, reply) => {
        const body = z.object({
            holderName: z.string().min(1).max(200).optional(),
            holderEmail: z.string().email().toLowerCase(),
            credentialType: z.string().min(1).max(100),
            field: z.string().max(100).optional(),
            notes: z.string().max(1000).optional(),
            issueDate: z.string(),
            expiryDate: z.string().optional(),
        }).safeParse(req.body)

       if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

// ── 2FA enforcement gate ─────────────────────────────
const issuerProfile = await db.issuerProfile.findUnique({
    where: { id: req.issuerId! },
    select: { twoFactorRequired: true },
})
const issuerUser = await db.user.findUnique({
    where: { id: req.userId! },
    select: { twoFactorEnabled: true },
})
if (issuerProfile?.twoFactorRequired && !issuerUser?.twoFactorEnabled) {
    return reply.status(403).send({
        error: 'Two-factor authentication required',
        message: 'Enable two-factor authentication before issuing credentials. Go to Institution Settings → Security.',
        code: 'TOTP_REQUIRED',
    })
}
const d = body.data
const issuerId = req.issuerId!
const id = generateCredentialId()

        const issueDateISO = new Date(d.issueDate + (d.issueDate.includes('T') ? '' : 'T00:00:00.000Z')).toISOString()
        const expiryDateISO = d.expiryDate
            ? new Date(d.expiryDate + (d.expiryDate.includes('T') ? '' : 'T00:00:00.000Z')).toISOString()
            : null

        let holderName = d.holderName
        if (!holderName) {
            const holderUser = await db.user.findUnique({
                where: { email: d.holderEmail },
                select: { firstName: true, lastName: true, email: true },
            })
            holderName = holderUser
                ? ([holderUser.firstName, holderUser.lastName].filter(Boolean).join(' ') || holderUser.email)
                : d.holderEmail
        }

        const sha256Hash = hashCredential({
            id, issuerId, holderName,
            holderEmail: d.holderEmail,
            credentialType: d.credentialType,
            field: d.field ?? null,
            issueDate: issueDateISO,
            expiryDate: expiryDateISO,
            notes: d.notes ?? null,
        })

        const credential = await db.credential.create({
            data: {
                id, issuerId, holderName,
                holderEmail: d.holderEmail,
                credentialType: d.credentialType,
                field: d.field ?? null,
                notes: d.notes ?? null,
                issueDate: new Date(issueDateISO),
                expiryDate: expiryDateISO ? new Date(expiryDateISO) : null,
                sha256Hash,
                status: 'ACTIVE',
            },
            select: { id: true, credentialType: true, holderName: true, holderEmail: true, issueDate: true, expiryDate: true, sha256Hash: true, status: true },
        })

        const anchorJob = await anchorQueue.add('anchor', { credentialId: id, sha256Hash })
        await db.credential.update({ where: { id }, data: { anchorJobId: anchorJob.id } })

        const issuer = await db.issuerProfile.findUnique({ where: { id: issuerId }, select: { institutionName: true } })
        await emailQueue.add('credential_issued', {
            type: 'credential_issued',
            to: d.holderEmail,
            data: {
                holderName,
                credentialType: d.credentialType,
                issuerName: issuer?.institutionName ?? '',
                credentialId: id,
                verifyUrl: `${env.FRONTEND_URL}/pages/verify.html?credential_id=${id}`,
            },
        })

        audit({ action: 'CREDENTIAL_ISSUED', req, targetType: 'credential', targetId: id, metadata: { credentialType: d.credentialType, holderEmail: d.holderEmail } })

        return reply.status(201).send({ ...credential, anchorStatus: 'queued' })
    })

    // ── VERIFY BY CREDENTIAL ID ───────────────────────────────
    app.get('/verify', { preHandler: authenticateOptional }, async (req, reply) => {
        const query = req.query as Record<string, string>
        const credentialId = query['credential_id']
        if (!credentialId) return reply.status(400).send({ error: 'Bad request', message: 'credential_id required' })

        trackVerificationRate(req).catch(() => { })

        const credential = await db.credential.findUnique({
            where: { id: credentialId },
            include: { issuer: { select: { id: true, institutionName: true, institutionType: true, status: true } } },
        })

        if (!credential) {
            await db.verificationLog.create({
                data: {
                    credentialId,
                    verifierId: req.verifierId ?? null,
                    apiKeyId: req.apiKeyId ?? null,
                    method: deriveMethod(req),
                    result: 'REVOKED',
                    hashValid: false,
                    issuerApproved: false,
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent']?.slice(0, 500) ?? null,
                },
            }).catch(() => { })
            return reply.status(404).send({ error: 'Not found', message: 'Credential not found' })
        }

        const recomputedHash = hashCredential({
            id: credential.id,
            issuerId: credential.issuerId,
            holderName: credential.holderName,
            holderEmail: credential.holderEmail,
            credentialType: credential.credentialType,
            field: credential.field,
            issueDate: credential.issueDate.toISOString(),
            expiryDate: credential.expiryDate?.toISOString() ?? null,
            notes: credential.notes,
        })
        const hashValid = recomputedHash === credential.sha256Hash

        let onChainValid: boolean | null = null
        if (credential.txHash && hashValid) {
            onChainValid = await verifyHashOnChain(credential.txHash, credential.sha256Hash)
                .catch(() => null)
        }

        const authentic = hashValid && (onChainValid !== false)
        const issuerApproved = credential.issuer.status === 'APPROVED'
        const isExpired = credential.expiryDate && credential.expiryDate < new Date()
        const effectiveStatus = isExpired && credential.status === 'ACTIVE' ? 'EXPIRED' : credential.status
        const method = deriveMethod(req)

        await db.verificationLog.create({
            data: {
                credentialId: credential.id,
                verifierId: req.verifierId ?? null,
                apiKeyId: req.apiKeyId ?? null,
                method,
                result: effectiveStatus as any,
                hashValid: authentic,
                issuerApproved,
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']?.slice(0, 500) ?? null,
            },
        })

        if (req.verifierId) {
            const webhooks = await db.webhook.findMany({
                where: { verifierId: req.verifierId, isActive: true, events: { has: 'credential.verified' } },
                select: { id: true },
            })
            for (const wh of webhooks) {
                await webhookQueue.add('webhook', {
                    webhookId: wh.id,
                    event: 'credential.verified',
                    payload: { credentialId: credential.id, result: effectiveStatus, hashValid: authentic, issuerApproved },
                })
            }
        }

        const response: Record<string, unknown> = {
            credential_id: credential.id,
            credential_type: credential.credentialType,
            status: effectiveStatus,
            authentic,
            hash_valid: hashValid,
            on_chain_valid: onChainValid,
            issuer_approved: issuerApproved,
            holder_name: credential.holderName,
            issue_date: credential.issueDate.toISOString(),
            expiry_date: credential.expiryDate?.toISOString() ?? null,
            issuer: {
                name: credential.issuer.institutionName,
                type: credential.issuer.institutionType,
                status: credential.issuer.status,
            },
            blockchain: {
                network: credential.txHash ? (credential.blockchainNetwork ?? 'polygon-mainnet') : null,
                sha256_hash: credential.sha256Hash,
                tx_hash: credential.txHash ?? null,
                anchored_at: credential.anchoredAt?.toISOString() ?? null,
            },
            verified_at: new Date().toISOString(),
        }

        if (req.userId || req.apiKeyId) response['holder_email'] = credential.holderEmail

        return reply.status(200).send(response)
    })

    // ── VERIFY BY SHARE TOKEN ─────────────────────────────────
    app.get('/verify-by-share', async (req, reply) => {
        const query = req.query as Record<string, string>
        const shareToken = query['share_token']
        if (!shareToken) return reply.status(400).send({ error: 'Bad request', message: 'share_token required' })

        trackVerificationRate(req).catch(() => { })

        const tokenHash = sha256(shareToken)
        const grant = await db.shareGrant.findUnique({
            where: { tokenHash },
            include: {
                credential: {
                    include: {
                        issuer: { select: { id: true, institutionName: true, institutionType: true, status: true } },
                    },
                },
            },
        })

        if (!grant) {
            return reply.status(404).send({ error: 'Not found', message: 'Share link not found or has been revoked' })
        }

        if (grant.isRevoked) {
            return reply.status(410).send({ error: 'Gone', message: 'This share link has been revoked by the credential holder' })
        }

        if (grant.expiresAt && grant.expiresAt < new Date()) {
            return reply.status(410).send({ error: 'Gone', message: 'This share link has expired' })
        }

        await db.shareGrant.update({
            where: { id: grant.id },
            data: { lastAccessedAt: new Date(), accessCount: { increment: 1 } },
        })

        const credential = grant.credential

        const recomputedHash = hashCredential({
            id: credential.id,
            issuerId: credential.issuerId,
            holderName: credential.holderName,
            holderEmail: credential.holderEmail,
            credentialType: credential.credentialType,
            field: credential.field,
            issueDate: credential.issueDate.toISOString(),
            expiryDate: credential.expiryDate?.toISOString() ?? null,
            notes: credential.notes,
        })
        const hashValid = recomputedHash === credential.sha256Hash

        let onChainValid: boolean | null = null
        if (credential.txHash && hashValid) {
            onChainValid = await verifyHashOnChain(credential.txHash, credential.sha256Hash)
                .catch(() => null)
        }

        const authentic = hashValid && (onChainValid !== false)
        const issuerApproved = credential.issuer.status === 'APPROVED'
        const isExpired = credential.expiryDate && credential.expiryDate < new Date()
        const effectiveStatus = isExpired && credential.status === 'ACTIVE' ? 'EXPIRED' : credential.status

        return reply.status(200).send({
            credential_id: credential.id,
            credential_type: credential.credentialType,
            field: credential.field ?? null,
            notes: credential.notes ?? null,
            status: effectiveStatus,
            authentic,
            hash_valid: hashValid,
            on_chain_valid: onChainValid,
            issuer_approved: issuerApproved,
            holder_name: credential.holderName,
            holder_email: credential.holderEmail,
            issue_date: credential.issueDate.toISOString(),
            expiry_date: credential.expiryDate?.toISOString() ?? null,
            issuer: {
                name: credential.issuer.institutionName,
                type: credential.issuer.institutionType,
                status: credential.issuer.status,
            },
            blockchain: {
                network: credential.txHash ? (credential.blockchainNetwork ?? 'polygon-mainnet') : null,
                sha256_hash: credential.sha256Hash,
                tx_hash: credential.txHash ?? null,
                anchored_at: credential.anchoredAt?.toISOString() ?? null,
            },
            share: {
                granted_to: grant.recipientEmail || null,
                expires_at: grant.expiresAt?.toISOString() ?? null,
                access_count: grant.accessCount + 1,
            },
            verified_at: new Date().toISOString(),
        })
    })

    // ── GET BY ID ─────────────────────────────────────────────
    app.get('/:id', { preHandler: authenticate }, async (req, reply) => {
        const { id } = req.params as { id: string }
        const cred = await db.credential.findUnique({
            where: { id },
            include: { issuer: { select: { institutionName: true, status: true } } },
        })

        if (!cred) return reply.status(404).send({ error: 'Not found' })

        const isOwner =
            (req.userRole === 'ISSUER' && cred.issuerId === req.issuerId) ||
            (req.userRole === 'HOLDER' && cred.holderUserId === req.userId) ||
            req.userRole === 'ADMIN'
        if (!isOwner) return reply.status(403).send({ error: 'Forbidden' })

        return reply.status(200).send(cred)
    })

    // ── REVOKE ────────────────────────────────────────────────
    app.patch('/:id/revoke', { preHandler: [authenticate, requireIssuer, requireApprovedIssuer] }, async (req, reply) => {
        const { id } = req.params as { id: string }
        const body = z.object({
            reason: z.enum(['disciplinary_action', 'issued_in_error', 'credential_transferred', 'fraud_or_misuse', 'other']),
            notes: z.string().max(500).optional(),
        }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const cred = await db.credential.findUnique({
            where: { id },
            include: { issuer: { select: { institutionName: true } } },
        })
        if (!cred) return reply.status(404).send({ error: 'Not found' })
        if (cred.issuerId !== req.issuerId) return reply.status(403).send({ error: 'Forbidden' })
        if (cred.status === 'REVOKED') return reply.status(409).send({ error: 'Conflict', message: 'Already revoked' })

        await db.credential.update({
            where: { id },
            data: { status: 'REVOKED', revokedAt: new Date(), revokedById: req.userId, revocationReason: body.data.reason, revocationCode: body.data.notes ?? null },
        })

        await emailQueue.add('credential_revoked', {
            type: 'credential_revoked',
            to: cred.holderEmail,
            data: { holderName: cred.holderName, credentialType: cred.credentialType, issuerName: cred.issuer.institutionName, reason: body.data.reason.replace(/_/g, ' ') },
        })

        const verifiers = await db.verificationLog.findMany({
            where: { credentialId: id },
            select: { verifierId: true },
            distinct: ['verifierId'],
        })
        for (const v of verifiers) {
            if (!v.verifierId) continue
            const hooks = await db.webhook.findMany({
                where: { verifierId: v.verifierId, isActive: true, events: { has: 'credential.revoked' } },
                select: { id: true },
            })
            for (const wh of hooks) {
                await webhookQueue.add('webhook', { webhookId: wh.id, event: 'credential.revoked', payload: { credentialId: id, reason: body.data.reason } })
            }
        }

        audit({ action: 'CREDENTIAL_REVOKED', req, targetType: 'credential', targetId: id, metadata: { reason: body.data.reason } })

        return reply.status(200).send({ message: 'Credential revoked', credentialId: id })
    })

    // ── FREEZE ────────────────────────────────────────────────
    app.patch('/:id/freeze', { preHandler: [authenticate, requireIssuer, requireApprovedIssuer] }, async (req, reply) => {
        const { id } = req.params as { id: string }
        const body = z.object({ reason: z.string().min(1).max(500) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        const cred = await db.credential.findUnique({ where: { id }, select: { issuerId: true, status: true } })
        if (!cred) return reply.status(404).send({ error: 'Not found' })
        if (cred.issuerId !== req.issuerId) return reply.status(403).send({ error: 'Forbidden' })
        if (cred.status !== 'ACTIVE') return reply.status(409).send({ error: 'Conflict', message: 'Only active credentials can be frozen' })

        await db.credential.update({ where: { id }, data: { status: 'FROZEN', frozenAt: new Date(), frozenById: req.userId, frozenReason: body.data.reason } })
        audit({ action: 'CREDENTIAL_FROZEN', req, targetType: 'credential', targetId: id })

        return reply.status(200).send({ message: 'Credential frozen', credentialId: id })
    })

    // ── UNFREEZE ──────────────────────────────────────────────
    app.patch('/:id/unfreeze', { preHandler: [authenticate, requireIssuer, requireApprovedIssuer] }, async (req, reply) => {
        const { id } = req.params as { id: string }
        const cred = await db.credential.findUnique({ where: { id }, select: { issuerId: true, status: true } })
        if (!cred) return reply.status(404).send({ error: 'Not found' })
        if (cred.issuerId !== req.issuerId) return reply.status(403).send({ error: 'Forbidden' })
        if (cred.status !== 'FROZEN') return reply.status(409).send({ error: 'Conflict', message: 'Credential is not frozen' })

        await db.credential.update({ where: { id }, data: { status: 'ACTIVE', frozenAt: null, frozenById: null, frozenReason: null } })
        audit({ action: 'CREDENTIAL_UNFROZEN', req, targetType: 'credential', targetId: id })

        return reply.status(200).send({ message: 'Credential unfrozen', credentialId: id })
    })

    // ── BATCH VERIFY ──────────────────────────────────────────
    app.post('/verify/batch', { preHandler: [authenticateApiKey, requireScope('batch')] }, async (req, reply) => {
        const body = z.object({ credential_ids: z.array(z.string()).min(1).max(500) }).safeParse(req.body)
        if (!body.success) return reply.status(400).send({ error: 'Validation error', issues: body.error.issues })

        trackVerificationRate(req).catch(() => { })

        const ids = body.data.credential_ids
        const credentials = await db.credential.findMany({
            where: { id: { in: ids } },
            include: { issuer: { select: { institutionName: true, status: true } } },
        })
        const credMap = new Map(credentials.map(c => [c.id, c]))

        const results = ids.map(id => {
            const c = credMap.get(id)
            if (!c) return { credential_id: id, status: 'not_found', authentic: false, hash_valid: false, issuer_approved: false }

            const recomputed = hashCredential({ id: c.id, issuerId: c.issuerId, holderName: c.holderName, holderEmail: c.holderEmail, credentialType: c.credentialType, field: c.field, issueDate: c.issueDate.toISOString(), expiryDate: c.expiryDate?.toISOString() ?? null, notes: c.notes })
            const isExpired = c.expiryDate && c.expiryDate < new Date()
            const effectiveStatus = isExpired && c.status === 'ACTIVE' ? 'EXPIRED' : c.status
            const hashValid = recomputed === c.sha256Hash
            const issuerApproved = c.issuer.status === 'APPROVED'

            return {
                credential_id: id,
                credential_type: c.credentialType,
                holder_name: c.holderName,
                status: effectiveStatus.toLowerCase(),
                authentic: hashValid && issuerApproved && effectiveStatus === 'ACTIVE',
                hash_valid: hashValid,
                issuer_approved: issuerApproved,
                issuer_name: c.issuer.institutionName,
                issue_date: c.issueDate.toISOString(),
            }
        })

        audit({ action: 'BULK_VERIFICATION_STARTED', req, metadata: { count: ids.length } })

        return reply.status(200).send({ results, count: results.length, verified_at: new Date().toISOString() })
    })
}

// ── HELPERS ───────────────────────────────────────────────────
function deriveMethod(req: any): 'DASHBOARD' | 'API' | 'QR_SCAN' | 'BULK_CSV' | 'SELF_VERIFY' {
    if (req.apiKeyId) return 'API'
    const query = req.query as Record<string, string>
    if (query['share_token']) return 'QR_SCAN'
    return 'DASHBOARD'
}