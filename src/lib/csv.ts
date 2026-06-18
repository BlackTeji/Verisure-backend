export function parseCsv(text: string): Record<string, string>[] {
    const rows = splitCsvRows(text)
    if (rows.length === 0) return []

    const header = rows[0].map(h => h.trim())
    const out: Record<string, string>[] = []

    for (let i = 1; i < rows.length; i++) {
        const row = rows[i]
        if (row.length === 1 && row[0].trim() === '') continue

        const record: Record<string, string> = {}
        header.forEach((h, idx) => {
            record[h] = (row[idx] ?? '').trim()
        })
        out.push(record)
    }

    return out
}

function splitCsvRows(text: string): string[][] {
    const rows: string[][] = []
    let row: string[] = []
    let field = ''
    let inQuotes = false

    const normalised = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')

    for (let i = 0; i < normalised.length; i++) {
        const ch = normalised[i]

        if (inQuotes) {
            if (ch === '"') {
                if (normalised[i + 1] === '"') {
                    field += '"'
                    i++
                } else {
                    inQuotes = false
                }
            } else {
                field += ch
            }
            continue
        }

        if (ch === '"') {
            inQuotes = true
        } else if (ch === ',') {
            row.push(field)
            field = ''
        } else if (ch === '\n') {
            row.push(field)
            field = ''
            rows.push(row)
            row = []
        } else {
            field += ch
        }
    }

    row.push(field)
    if (row.length > 1 || row[0] !== '') rows.push(row)

    return rows
}