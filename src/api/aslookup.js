/**
 * Hexa Sentinel — ASN → Country / Holder Lookup
 *
 * Source:
 *   RIPE Stat AS Overview API
 *
 * Purpose:
 *   Resolve an attacker ASN to:
 *     - country code
 *     - holder / organization name
 *     - normalized ASN
 *
 * Design goals:
 *   - Never invent a country.
 *   - Never default an unknown ASN to India.
 *   - Normalize AS numbers consistently.
 *   - Deduplicate simultaneous requests.
 *   - Cache successful results.
 *   - Briefly cache failed lookups.
 *   - Keep ASN enrichment optional so the BGP detection pipeline
 *     continues working when RIPE Stat is unavailable.
 */

const RIPE_STAT_BASE =
  'https://stat.ripe.net/data/as-overview/data.json'

const SUCCESS_CACHE_TTL_MS = 30 * 60 * 1000
const FAILURE_CACHE_TTL_MS = 60 * 1000
const REQUEST_TIMEOUT_MS = 5000

const CACHE = new Map()
const PENDING = new Map()

/**
 * Normalize an ASN into:
 *
 *   AS12345
 *
 * Supported:
 *   12345
 *   "12345"
 *   "AS12345"
 *   "as12345"
 *   " AS12345 "
 */
function normalizeASN(asn) {
  if (asn === null || asn === undefined) {
    return null
  }

  const value = String(asn)
    .trim()
    .toUpperCase()

  const numeric = value.replace(/^AS/, '')

  if (!/^\d+$/.test(numeric)) {
    return null
  }

  const number = Number(numeric)

  // ASN is a 32-bit unsigned number.
  if (!Number.isSafeInteger(number)) {
    return null
  }

  if (number < 0 || number > 4294967295) {
    return null
  }

  return `AS${number}`
}

/**
 * Return only the numeric ASN portion.
 */
function getASNNumber(asn) {
  const normalized = normalizeASN(asn)

  if (!normalized) {
    return null
  }

  return normalized.slice(2)
}

/**
 * Normalize a country code.
 *
 * Example:
 *   "in" → "IN"
 *   "CN" → "CN"
 *
 * Invalid values return null.
 */
function normalizeCountry(country) {
  if (!country) {
    return null
  }

  const value = String(country)
    .trim()
    .toUpperCase()

  if (!/^[A-Z]{2}$/.test(value)) {
    return null
  }

  return value
}

/**
 * Fallback country extraction.
 *
 * Some RIPE holder strings can contain:
 *
 *   "Example Telecom, CN"
 *   "Example Network, IN"
 */
function extractCountryFromHolder(holder) {
  if (!holder) {
    return null
  }

  const match = String(holder).match(/,\s*([A-Z]{2})$/i)

  if (!match) {
    return null
  }

  return normalizeCountry(match[1])
}

/**
 * Read an entry from cache.
 */
function getCached(key) {
  const entry = CACHE.get(key)

  if (!entry) {
    return undefined
  }

  if (Date.now() >= entry.expiresAt) {
    CACHE.delete(key)
    return undefined
  }

  return entry.value
}

/**
 * Store an entry in cache.
 */
function setCached(key, value, ttl) {
  CACHE.set(key, {
    value,
    expiresAt: Date.now() + ttl,
  })
}

/**
 * Fetch ASN information from RIPE Stat.
 */
async function fetchASNOverview(asnNumber, normalizedASN) {
  try {
    const url =
      `${RIPE_STAT_BASE}?resource=${encodeURIComponent(normalizedASN)}`

    const response = await fetch(url, {
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: {
        Accept: 'application/json',
      },
    })

    if (!response.ok) {
      throw new Error(
        `RIPE Stat HTTP ${response.status}`
      )
    }

    const json = await response.json()
    const data = json?.data

    if (!data || typeof data !== 'object') {
      throw new Error(
        'RIPE Stat returned invalid data'
      )
    }

    const holder =
      typeof data.holder === 'string'
        ? data.holder.trim()
        : ''

    /*
     * Prefer RIPE's announced country.
     *
     * Fallback order:
     *   1. announced_country
     *   2. country
     *   3. country embedded in holder name
     */
    const country =
      normalizeCountry(data.announced_country) ??
      normalizeCountry(data.country) ??
      extractCountryFromHolder(holder)

    return {
      asn: normalizedASN,
      country: country ?? 'XX',
      holder: holder || 'Unknown ASN',
    }
  } catch (error) {
    console.warn(
      `[Hexa Sentinel ASN] Failed to resolve ${normalizedASN}:`,
      error?.message ?? error
    )

    return null
  }
}

/**
 * Resolve an ASN to country and holder information.
 *
 * Example:
 *
 *   const result = await lookupASCountry('AS138886')
 *
 * Returns:
 *
 *   {
 *     asn: 'AS138886',
 *     country: 'IN',
 *     holder: 'Example Network'
 *   }
 *
 * or null if RIPE Stat could not resolve it.
 */
export async function lookupASCountry(asn) {
  const normalizedASN = normalizeASN(asn)

  if (!normalizedASN) {
    console.warn(
      '[Hexa Sentinel ASN] Invalid ASN:',
      asn
    )

    return null
  }

  const asnNumber = getASNNumber(normalizedASN)

  if (!asnNumber) {
    return null
  }

  /*
   * Check cached result.
   *
   * Important:
   * getCached() can legitimately return null because a failed
   * lookup is negatively cached.
   */
  const cached = getCached(normalizedASN)

  if (cached !== undefined) {
    return cached
  }

  /*
   * Deduplicate simultaneous requests.
   *
   * If five incidents all contain AS4134 at approximately the
   * same time, only one RIPE request is sent.
   */
  if (PENDING.has(normalizedASN)) {
    return PENDING.get(normalizedASN)
  }

  const promise = fetchASNOverview(
    asnNumber,
    normalizedASN
  )
    .then(result => {
      if (result) {
        setCached(
          normalizedASN,
          result,
          SUCCESS_CACHE_TTL_MS
        )
      } else {
        /*
         * Short negative cache.
         *
         * This prevents a failed RIPE request from being retried
         * every time the UI renders the same incident.
         */
        setCached(
          normalizedASN,
          null,
          FAILURE_CACHE_TTL_MS
        )
      }

      return result
    })
    .catch(() => {
      setCached(
        normalizedASN,
        null,
        FAILURE_CACHE_TTL_MS
      )

      return null
    })
    .finally(() => {
      PENDING.delete(normalizedASN)
    })

  PENDING.set(normalizedASN, promise)

  return promise
}

/**
 * Resolve multiple ASNs in parallel.
 *
 * Useful when Hexa Sentinel receives several incidents
 * during a BGP event.
 */
export async function lookupASCountries(asns = []) {
  const uniqueASNs = [
    ...new Set(
      asns
        .map(normalizeASN)
        .filter(Boolean)
    ),
  ]

  if (uniqueASNs.length === 0) {
    return []
  }

  const results = await Promise.all(
    uniqueASNs.map(asn =>
      lookupASCountry(asn)
    )
  )

  return results.filter(Boolean)
}

/**
 * Common ASNs used during development/demo/testing.
 *
 * These are only cache warm-up entries.
 *
 * They do NOT determine whether an ASN is malicious.
 */
const COMMON_ASNS = [
  '4134',    // China Telecom
  '4837',    // China Unicom
  '9808',    // China Mobile
  '45595',   // PTCL Pakistan
  '17557',   // PTCL
  '58453',   // China Telecom Next Generation
  '23969',   // Thailand
  '38909',   // Indian network
  '137354',
  '138886',
  '135012',
  '141873',
  '7018',    // AT&T
  '3320',    // Deutsche Telekom
  '1221',    // Telstra
  '2516',    // KDDI
  '6762',    // Telecom Italia
  '8452',    // Telecom Egypt
  '174',     // Cogent
  '3356',    // Lumen
]

/**
 * Pre-warm the ASN country cache.
 *
 * Called during Hexa Sentinel application startup.
 *
 * This runs asynchronously and does not block the main
 * BGP detection pipeline.
 */
export async function prewarmASCache() {
  console.log(
    '[Hexa Sentinel ASN] Pre-warming RIPE Stat ASN cache...'
  )

  const results = await Promise.allSettled(
    COMMON_ASNS.map(asn =>
      lookupASCountry(`AS${asn}`)
    )
  )

  const resolved = results.filter(
    result =>
      result.status === 'fulfilled' &&
      result.value !== null
  ).length

  console.log(
    `[Hexa Sentinel ASN] Pre-warmed ` +
    `${resolved}/${COMMON_ASNS.length} ASN lookups`
  )

  return resolved
}

/**
 * Clear all ASN cache entries.
 *
 * Useful for development/testing.
 */
export function clearASCache() {
  CACHE.clear()
}

/**
 * Return current ASN cache statistics.
 */
export function getASCacheStatus() {
  return {
    cached: CACHE.size,
    pending: PENDING.size,
  }
}
