import { Redis } from 'ioredis'
import { env } from '../config/env.js'
import { logger } from './logger.js'

const make = (name: string) => {
    const c = new Redis(env.REDIS_URL, {
        ...(env.REDIS_PASSWORD ? { password: env.REDIS_PASSWORD } : {}),
        maxRetriesPerRequest: null,
        enableReadyCheck: true,
        lazyConnect: false,
        retryStrategy: (times: number) => {
            if (times > 10) { logger.error({ name }, 'redis: max retries'); return null }
            const delay = Math.min(times * 200, 3000)
            logger.warn({ name, attempt: times, delay }, 'redis: retry')
            return delay
        },
    })
    c.on('connect', () => logger.info({ name }, 'redis: connected'))
    c.on('ready', () => logger.info({ name }, 'redis: ready'))
    c.on('error', (err: Error) => logger.error({ name, err }, 'redis: error'))
    c.on('close', () => logger.warn({ name }, 'redis: closed'))
    return c
}

export const redis = make('app')
export const redisSub = make('sub')

export const keys = {
    tokenBlacklist: (jti: string) => `vrs:blacklist:${jti}`,
    rateLimit: (ip: string, r: string) => `vrs:rl:${r}:${ip}`,
    issuerStatus: (id: string) => `vrs:issuer:${id}:status`,
    apiKey: (hash: string) => `vrs:apikey:${hash}`,
    fraudCount: (ip: string) => `vrs:fraud:${ip}`,
    blockedIp: (ip: string) => `vrs:blocked:${ip}`,
} as const