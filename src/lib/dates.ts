const ISO_DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})?$/

export function isStrictIsoDateString(value: string): boolean {
    const v = value.trim()
    if (!ISO_DATE_ONLY.test(v) && !ISO_DATE_TIME.test(v)) return false
    const d = new Date(v)
    return !isNaN(d.getTime())
}

export function parseStrictIsoDate(value: string, fieldName = 'date'): Date {
    const v = value.trim()
    if (!ISO_DATE_ONLY.test(v) && !ISO_DATE_TIME.test(v)) {
        throw new Error(
            `Invalid ${fieldName} "${value}": expected ISO 8601 format (YYYY-MM-DD). ` +
            `Locale-specific formats like 2/17/2024 or 17/02/2024 are rejected because they are ambiguous.`
        )
    }
    const d = new Date(v)
    if (isNaN(d.getTime())) {
        throw new Error(`Invalid ${fieldName} "${value}": not a real calendar date.`)
    }
    return d
}