import { PrismaClient } from '@prisma/client'
import { scrypt, randomBytes } from 'crypto'
import { promisify } from 'util'

const db = new PrismaClient()
const scryptAsync = promisify(scrypt)

async function hashPassword(password: string): Promise<string> {
    const salt = randomBytes(32).toString('hex')
    const key = await scryptAsync(password, salt, 64) as Buffer
    return `${salt}:${key.toString('hex')}`
}

async function main() {
    const email = process.env['ADMIN_EMAIL'] ?? 'admin@verisure.ng'
    const pass = process.env['ADMIN_INITIAL_PASSWORD']

    if (!pass) {
        console.error('Set ADMIN_INITIAL_PASSWORD before seeding.')
        process.exit(1)
    }

    const existing = await db.user.findUnique({ where: { email } })
    if (existing) {
        console.log(`Admin already exists: ${email}`)
        return
    }

    const admin = await db.user.create({
        data: {
            email,
            passwordHash: await hashPassword(pass),
            role: 'ADMIN',
            firstName: 'VeriSure',
            lastName: 'Admin',
            emailVerified: true,
            isActive: true,
        },
    })

    console.log(`Admin created: ${admin.email} (${admin.id})`)
}

main()
    .catch(err => { console.error(err); process.exit(1) })
    .finally(() => db.$disconnect())