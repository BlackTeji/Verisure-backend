import { PrismaClient } from '@prisma/client'
import { logger } from './logger.js'
import { env } from '../config/env.js'

const createClient = () => {
    const client = new PrismaClient({
        log: env.NODE_ENV === 'development'
            ? [{ emit: 'event', level: 'query' }, { emit: 'event', level: 'warn' }, { emit: 'event', level: 'error' }]
            : [{ emit: 'event', level: 'warn' }, { emit: 'event', level: 'error' }],
    })

    if (env.NODE_ENV === 'development') {
        client.$on('query', e => logger.debug({ query: e.query, duration: e.duration }, 'db:query'))
    }
    client.$on('warn', e => logger.warn({ message: e.message }, 'db:warn'))
    client.$on('error', e => logger.error({ message: e.message }, 'db:error'))

    return client
}

const g = globalThis as unknown as { prisma: PrismaClient | undefined }
export const db: PrismaClient = g.prisma ?? createClient()
if (env.NODE_ENV !== 'production') g.prisma = db

process.on('beforeExit', async () => { await db.$disconnect() })