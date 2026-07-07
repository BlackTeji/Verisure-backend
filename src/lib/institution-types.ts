export const INSTITUTION_TYPES = [
    'Federal University',
    'State University',
    'Private University',
    'Polytechnic',
    'Professional Body',
    'Licensing Authority',
    'Government Agency',
    'Other',
] as const

export type InstitutionType = typeof INSTITUTION_TYPES[number]