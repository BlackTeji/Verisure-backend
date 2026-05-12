import {
    createHash, createCipheriv, createDecipheriv,
    randomBytes, timingSafeEqual, randomUUID,
} from 'crypto'
import { env } from '../config/env.js'

// ── IDs ───────────────────────────────────────────────────────
export function generateCredentialId(): string {
    const b = randomBytes(16).toString('hex')
    return `VS-${b.slice(0, 8)}-${b.slice(8, 12)}-${b.slice(12, 16)}-${b.slice(16, 20)}-${b.slice(20, 32)}`
}

// ── HASHING ───────────────────────────────────────────────────
export function sha256(data: string): string {
    return createHash('sha256').update(data, 'utf8').digest('hex')
}

function canonicalJSON(obj: Record<string, unknown>): string {
    const entries = Object.entries(obj)
        .filter(([, v]) => v !== null && v !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))

    const parts = entries.map(([k, v]) => {
        const key = JSON.stringify(k)
        const value = typeof v === 'string' ? JSON.stringify(v) : String(v)
        return `${key}:${value}`
    })
    return '{' + parts.join(',') + '}'
}

export function hashCredential(f: {
    id: string
    issuerId: string
    holderName: string
    holderEmail: string
    credentialType: string
    field?: string | null
    issueDate: string 
    expiryDate?: string | null
    notes?: string | null
}): string {
    return sha256(canonicalJSON(f as unknown as Record<string, unknown>))
}

export function secureCompare(a: string, b: string): boolean {
    const ba = Buffer.from(a, 'hex')
    const bb = Buffer.from(b, 'hex')
    if (ba.length !== bb.length) return false
    return timingSafeEqual(ba, bb)
}

// ── API KEYS ──────────────────────────────────────────────────
export function generateApiKey(environment: 'live' | 'test') {
    const secret = randomBytes(32).toString('hex')
    const plaintext = `vs_${environment}_${secret}`
    return { plaintext, hash: sha256(plaintext), prefix: plaintext.slice(0, 16) }
}

// ── WEBHOOK SECRET ────────────────────────────────────────────
export function generateWebhookSecret(): string {
    return randomBytes(32).toString('hex')
}

// ── AES-256-GCM ───────────────────────────────────────────────
const ENC_KEY = Buffer.from(env.API_KEY_ENCRYPTION_KEY, 'hex')
const IV_LEN = 12
const TAG_LEN = 16

export function encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LEN)
    const cipher = createCipheriv('aes-256-gcm', ENC_KEY, iv)
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return iv.toString('hex') + tag.toString('hex') + enc.toString('hex')
}

export function decrypt(ciphertext: string): string {
    const iv = Buffer.from(ciphertext.slice(0, IV_LEN * 2), 'hex')
    const tag = Buffer.from(ciphertext.slice(IV_LEN * 2, IV_LEN * 2 + TAG_LEN * 2), 'hex')
    const enc = Buffer.from(ciphertext.slice(IV_LEN * 2 + TAG_LEN * 2), 'hex')
    const de = createDecipheriv('aes-256-gcm', ENC_KEY, iv)
    de.setAuthTag(tag)
    return de.update(enc).toString('utf8') + de.final('utf8')
}

// ── TOKENS ────────────────────────────────────────────────────
export function generateSecureToken(bytes = 32): string {
    return randomBytes(bytes).toString('base64url')
}

export function generateTotpSecret(): string {
    return randomBytes(20).toString('base64').replace(/[^A-Z2-7]/gi, '').toUpperCase().slice(0, 32)
}