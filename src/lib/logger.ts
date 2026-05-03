import pino from 'pino'
import { env } from '../config/env.js'

export const logger = pino({
    level: env.LOG_LEVEL,
    ...(env.LOG_PRETTY && env.NODE_ENV !== 'production'
        ? { transport: { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname' } } }
        : { formatters: { level: (label: string) => ({ level: label }) }, timestamp: pino.stdTimeFunctions.isoTime }),
    redact: {
        paths: ['req.headers.authorization', 'req.headers.cookie', 'body.password', 'body.passwordHash', 'body.privateKey', '*.password', '*.passwordHash', '*.twoFactorSecret', '*.privateKey'],
        censor: '[REDACTED]',
    },
})

export type Logger = typeof logger