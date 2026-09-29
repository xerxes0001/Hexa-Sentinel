/**
 * Hexa Sentinel — RPKI Validation
 *
 * Uses Cloudflare's public RPKI API:
 * GET https://rpki.cloudflare.com/api/v1/validity/{asn}/{prefix}
 *
 * States:
 *   valid     → ROA exists and origin is authorized
 *   invalid   → ROA exists but origin is NOT authorized
 *   not-found → no ROA exists for this prefix
 *   unknown   → API/network result could not be determined
 *
 * Important:
 * - Never repeatedly request the same ASN + prefix.
 * - 404 is a normal "no ROA found" result, not an API failure.
 * - Invalid/placeholder ASNs are never sent to the API.
 * - Failed requests are temporarily negative-cached.
 */

const CACHE = new Map()
const PENDING = new Map()

// Cache failed/network requests for one minute.
// This prevents repeated API calls when the Cloudflare endpoint
// is temporarily unavailable.
const FAIL_CACHE_MS = 60 * 1000

// Successful RPKI results.
const SUCCESS_CACHE_MS = 5 * 60 * 1000

// "No ROA found" is stable enough to cache longer.
const NOT_FOUND_CACHE_MS = 15 * 60 * 1000


// ─────────────────────────────────────────────────────────────
// Cache helper
// ─────────────────────────────────────────────────────────────

function cacheResult(key, result, ttlMs) {
  CACHE.set(key, result)

  setTimeout(() => {
    CACHE.delete(key)
  }, ttlMs)
}


// ─────────────────────────────────────────────────────────────
// ASN normalization
// ─────────────────────────────────────────────────────────────

function normalizeASN(asn) {
  const value = String(asn ?? '').trim()

  if (!value) return null

  // Accept:
  // AS55836
  // as55836
  // 55836
  const number = value.replace(/^AS/i, '')

  // Only real numeric ASNs are allowed.
  if (!/^\d+$/.test(number)) {
    return null
  }

  return number
}


// ─────────────────────────────────────────────────────────────
// Cache key
// ─────────────────────────────────────────────────────────────

function normalizeCacheKey(asn, prefix) {
  const asnNumber = normalizeASN(asn)

  if (!asnNumber || !prefix) {
    return null
  }

  return `${asnNumber}:${prefix}`
}


// ─────────────────────────────────────────────────────────────
// Main RPKI check
// ─────────────────────────────────────────────────────────────

export async function checkRPKI(asn, prefix) {
  const asnNumber = normalizeASN(asn)

  // Invalid / unknown ASN.
  // Do NOT send malformed requests to Cloudflare.
  if (!asnNumber || !prefix) {
    return null
  }

  const key = `${asnNumber}:${prefix}`

  // Existing cached result.
  //
  // IMPORTANT:
  // CACHE may intentionally contain null, so use .has()
  // instead of checking CACHE.get(key).
  if (CACHE.has(key)) {
    return CACHE.get(key)
  }

  // Same request already running.
  // Return the existing promise instead of creating another request.
  if (PENDING.has(key)) {
    return PENDING.get(key)
  }

  const promise = fetchRPKI(asnNumber, prefix, key)

  PENDING.set(key, promise)

  try {
    return await promise
  } finally {
    PENDING.delete(key)
  }
}


// ─────────────────────────────────────────────────────────────
// Cloudflare RPKI request
// ─────────────────────────────────────────────────────────────

async function fetchRPKI(asnNumber, prefix, key) {
  const url =
    `https://rpki.cloudflare.com/api/v1/validity/${asnNumber}/${prefix}`

  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(5000),
    })

    // ─────────────────────────────────────────────
    // 404 = no ROA
    //
    // This is NOT an API failure.
    // It simply means the prefix does not have
    // a Route Origin Authorization.
    // ─────────────────────────────────────────────

    if (response.status === 404) {
      const result = {
        valid: false,
        invalid: false,
        unknown: true,

        state: 'not-found',

        reason:
          'No Route Origin Authorization found for this prefix',

        asn: `AS${asnNumber}`,
        prefix,
      }

      cacheResult(
        key,
        result,
        NOT_FOUND_CACHE_MS
      )

      return result
    }


    // ─────────────────────────────────────────────
    // Other HTTP errors
    // ─────────────────────────────────────────────

    if (!response.ok) {
      console.warn(
        `[Hexa Sentinel RPKI] ${prefix}: ` +
        `HTTP ${response.status}`
      )

      // Negative cache.
      // Prevents repeated requests during outages,
      // rate limits or temporary server errors.
      cacheResult(
        key,
        null,
        FAIL_CACHE_MS
      )

      return null
    }


    // ─────────────────────────────────────────────
    // Parse response
    // ─────────────────────────────────────────────

    const data = await response.json()

    const state =
      data?.result?.validity?.state ?? 'unknown'

    const reason =
      data?.result?.validity?.reason ?? null


    // ─────────────────────────────────────────────
    // Normalize API result
    // ─────────────────────────────────────────────

    const result = {
      valid: state === 'valid',

      invalid: state === 'invalid',

      unknown:
        state === 'unknown' ||
        state === 'not-found',

      state,

      reason,

      asn: `AS${asnNumber}`,

      prefix,
    }


    // Successful response.
    cacheResult(
      key,
      result,
      SUCCESS_CACHE_MS
    )

    return result

  } catch (error) {

    // AbortError generally means timeout.
    // Don't spam the console for expected timeout failures.
    if (error?.name !== 'AbortError') {
      console.warn(
        `[Hexa Sentinel RPKI] ${prefix}: ` +
        `network error — ${error?.message ?? 'unknown error'}`
      )
    }

    // Negative-cache network failures.
    cacheResult(
      key,
      null,
      FAIL_CACHE_MS
    )

    return null
  }
}


// ─────────────────────────────────────────────────────────────
// Incident helper
// ─────────────────────────────────────────────────────────────
//
// App.jsx can call:
//
//   const rpki = await preCheckRPKI(incident)
//
// The expected incident structure is:
//
// incident.victim.asn
// incident.prefix
//
// Example:
//
// {
//   victim: {
//     asn: "AS55836"
//   },
//   prefix: "157.32.10.0/24"
// }
// ─────────────────────────────────────────────────────────────

export async function preCheckRPKI(incident) {
  if (!incident) {
    return null
  }

  const asn = incident?.victim?.asn
  const prefix = incident?.prefix

  if (!asn || !prefix) {
    return null
  }

  return checkRPKI(asn, prefix)
}


// ─────────────────────────────────────────────────────────────
// Optional helper for UI/debugging
// ─────────────────────────────────────────────────────────────

export function getRPKICacheStats() {
  return {
    cachedResults: CACHE.size,
    pendingRequests: PENDING.size,
  }
}


// ─────────────────────────────────────────────────────────────
// Optional cache clear
// Useful during development/testing.
// ─────────────────────────────────────────────────────────────

export function clearRPKICache() {
  CACHE.clear()
  PENDING.clear()
}
