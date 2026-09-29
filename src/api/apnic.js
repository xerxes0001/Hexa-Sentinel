/**
 * APNIC Indian Prefix Database — SnapShield
 *
 * Responsibilities:
 *   1. Load Indian IPv4 delegation data from APNIC.
 *   2. Match prefixes to known Indian ASNs.
 *   3. NEVER silently assign an unknown prefix to Reliance Jio.
 *   4. Mark unresolved Indian ranges as unknown.
 *   5. Resolve unknown prefixes through RIPE Stat when possible.
 *
 * Important:
 *   This module is enrichment only.
 *   It does NOT decide whether traffic is malicious.
 *   BGP anomaly detection and ONNX/NPU classification happen elsewhere.
 */

import { INDIAN_ASNS } from '../data/indianASNs.js'

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────

let prefixMap = null
let loaded = false
let loading = false

// Successful RIPE lookups are cached for one hour.
const asnResolutionCache = new Map()

const RIPE_CACHE_TTL_MS = 60 * 60 * 1000

// ─────────────────────────────────────────────────────────────────────────────
// Unknown ASN representation
// ─────────────────────────────────────────────────────────────────────────────

function createUnknownASN(prefix, name = 'Indian Network') {
  return {
    asn: 'AS-IN-UNKNOWN',
    name,
    sector: 'ISP',
    prefixes: [prefix],
    isUnknown: true,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RIPE Stat ASN resolution
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resolve the currently announced ASN for a prefix using RIPE Stat.
 *
 * Example:
 *   resolveRealASN('103.21.244.0/24')
 *
 * Returns:
 *   {
 *     asn: 'AS12345',
 *     holder: 'Example Network',
 *     country: 'IN'
 *   }
 *
 * or null when no reliable result is available.
 */
export async function resolveRealASN(prefix) {
  if (!prefix || typeof prefix !== 'string') {
    return null
  }

  const ip = prefix.split('/')[0]

  if (!ip) {
    return null
  }

  // Successful cached result.
  const cached = asnResolutionCache.get(ip)

  if (cached) {
    if (Date.now() - cached.timestamp < RIPE_CACHE_TTL_MS) {
      return cached.result
    }

    asnResolutionCache.delete(ip)
  }

  try {
    const url =
      `https://stat.ripe.net/data/prefix-overview/data.json` +
      `?resource=${encodeURIComponent(prefix)}` +
      `&min_peers_seeing=3`

    const response = await fetch(
      url,
      {
        signal: AbortSignal.timeout(5000),
      }
    )

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }

    const json = await response.json()

    const asns = json?.data?.asns ?? []

    // Do NOT cache a failed lookup.
    //
    // RIPE may temporarily return no result. Caching that failure for
    // an hour would make the UI continue showing UNKNOWN even after
    // the prefix becomes resolvable.
    if (!Array.isArray(asns) || asns.length === 0) {
      return null
    }

    const firstASN = asns[0]

    if (!firstASN?.asn) {
      return null
    }

    const result = {
      asn: `AS${firstASN.asn}`,
      holder: firstASN.holder ?? 'Unknown',
      country:
        json?.data?.announced_by_country?.[0] ?? 'IN',
    }

    asnResolutionCache.set(ip, {
      result,
      timestamp: Date.now(),
    })

    // Prevent unbounded cache growth.
    if (asnResolutionCache.size > 1000) {
      const oldestKey = asnResolutionCache.keys().next().value

      if (oldestKey) {
        asnResolutionCache.delete(oldestKey)
      }
    }

    return result
  } catch (error) {
    console.warn(
      `[SnapShield RIPE] ASN resolution failed for ${prefix}:`,
      error?.message ?? error
    )

    return null
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardcoded fallback map
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a static fallback map.
 *
 * The fallback exists so SnapShield still works if:
 *   - APNIC is unavailable
 *   - CORS proxy is unavailable
 *   - the user is offline
 *   - CI is running without external network access
 *
 * IMPORTANT:
 * Unknown ranges are explicitly represented as unknown.
 * They are NEVER mapped to INDIAN_ASNS[0].
 */
function buildFallbackMap() {
  const map = new Map()

  // First add the explicitly known prefixes.
  for (const asn of INDIAN_ASNS) {
    if (!asn?.prefixes || !Array.isArray(asn.prefixes)) {
      continue
    }

    for (const prefix of asn.prefixes) {
      if (!prefix) continue

      map.set(prefix, asn)
    }
  }

  // Broad Indian ranges.
  //
  // Only ranges for which we have an explicit ASN are assigned an ASN.
  // The others remain explicitly UNKNOWN.
  const broadRanges = [
    ['14.96.0.0/11', 'AS9829', 'BSNL'],
    ['27.0.0.0/13', 'AS45271', 'Idea Cellular'],
    ['49.32.0.0/11', 'AS24560', 'Airtel India'],
    ['59.88.0.0/13', 'AS9829', 'BSNL'],

    ['101.0.0.0/11', null, 'Indian ISP'],
    ['103.0.0.0/8', null, 'Indian Network'],

    ['110.224.0.0/12', null, 'Indian ISP'],

    ['111.64.0.0/10', 'AS18101', 'Reliance Comm'],
    ['115.112.0.0/13', 'AS24560', 'Airtel India'],
    ['117.96.0.0/11', 'AS18101', 'Reliance Comm'],

    ['119.224.0.0/12', null, 'Indian ISP'],

    ['122.160.0.0/11', 'AS9829', 'BSNL'],
    ['125.16.0.0/12', 'AS9498', 'Bharti Airtel BB'],
    ['157.32.0.0/11', 'AS55836', 'Reliance Jio'],
    ['164.100.0.0/14', 'AS45758', 'NIC India'],
    ['180.64.0.0/10', 'AS9498', 'Bharti Airtel BB'],
    ['182.64.0.0/11', 'AS24560', 'Airtel India'],
    ['203.94.0.0/16', 'AS24560', 'Airtel India'],
  ]

  for (const [prefix, asnStr, name] of broadRanges) {
    // Never overwrite a more specific known prefix.
    if (map.has(prefix)) {
      continue
    }

    if (asnStr) {
      const match = INDIAN_ASNS.find(
        item => item?.asn === asnStr
      )

      if (match) {
        map.set(prefix, match)
        continue
      }

      // ASN is explicitly known in our range table even if it isn't
      // present in indianASNs.js.
      map.set(prefix, {
        asn: asnStr,
        name,
        sector: 'ISP',
        prefixes: [prefix],
        isUnknown: false,
      })

      continue
    }

    // No reliable ASN available.
    map.set(
      prefix,
      createUnknownASN(prefix, name)
    )
  }

  return map
}

// ─────────────────────────────────────────────────────────────────────────────
// CIDR helpers
// ─────────────────────────────────────────────────────────────────────────────

function parseCIDR(cidr) {
  if (!cidr || typeof cidr !== 'string') {
    throw new Error('Invalid CIDR')
  }

  const [ip, bitsString] = cidr.split('/')

  if (!ip || bitsString == null) {
    throw new Error(`Invalid CIDR: ${cidr}`)
  }

  const parts = ip.split('.').map(Number)
  const bits = Number.parseInt(bitsString, 10)

  if (
    parts.length !== 4 ||
    parts.some(
      part => !Number.isInteger(part) || part < 0 || part > 255
    )
  ) {
    throw new Error(`Invalid IPv4 address: ${ip}`)
  }

  if (
    !Number.isInteger(bits) ||
    bits < 0 ||
    bits > 32
  ) {
    throw new Error(`Invalid prefix length: ${bits}`)
  }

  return {
    parts,
    bits,
  }
}

function ipv4ToInt(parts) {
  return (
    (
      parts[0] * 256 * 256 * 256 +
      parts[1] * 256 * 256 +
      parts[2] * 256 +
      parts[3]
    ) >>> 0
  )
}

function ipInCIDR(ip, cidr) {
  try {
    const {
      parts: cidrParts,
      bits,
    } = parseCIDR(cidr)

    const ipParts = ip.split('.').map(Number)

    if (
      ipParts.length !== 4 ||
      ipParts.some(
        part => !Number.isInteger(part) ||
               part < 0 ||
               part > 255
      )
    ) {
      return false
    }

    const cidrInt = ipv4ToInt(cidrParts)
    const ipInt = ipv4ToInt(ipParts)

    const mask =
      bits === 0
        ? 0
        : (0xffffffff << (32 - bits)) >>> 0

    return (
      (cidrInt & mask) ===
      (ipInt & mask)
    )
  } catch {
    return false
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// APNIC data loading
// ─────────────────────────────────────────────────────────────────────────────

export async function loadAPNICData(onProgress) {
  if (loaded) {
    return
  }

  if (loading) {
    return
  }

  loading = true

  const APNIC_SOURCE_URL =
    'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'

  const PROXY_URLS = [
    `https://corsproxy.io/?url=${encodeURIComponent(
      APNIC_SOURCE_URL
    )}`,

    `https://api.allorigins.win/raw?url=${encodeURIComponent(
      APNIC_SOURCE_URL
    )}`,
  ]

  let text = null
  let lastError = null

  // ── Try live APNIC data ─────────────────────────────────────────────────

  for (const url of PROXY_URLS) {
    try {
      const response = await fetch(
        url,
        {
          signal: AbortSignal.timeout(10000),
        }
      )

      if (!response.ok) {
        throw new Error(
          `proxy fetch failed (HTTP ${response.status})`
        )
      }

      text = await response.text()

      if (!text || text.length < 100) {
        throw new Error('APNIC response was empty')
      }

      break
    } catch (error) {
      lastError = error

      console.warn(
        '[SnapShield APNIC] Proxy failed:',
        error?.message ?? error
      )
    }
  }

  // ── Build map ───────────────────────────────────────────────────────────

  try {
    // If APNIC failed, use the static fallback.
    if (text === null) {
      throw (
        lastError ??
        new Error('all APNIC proxies failed')
      )
    }

    const lines = text.split('\n')
    const map = buildFallbackMap()

    let matched = 0

    for (const line of lines) {
      if (!line.startsWith('apnic|IN|ipv4|')) {
        continue
      }

      const parts = line.split('|')

      if (parts.length < 5) {
        continue
      }

      const baseIP = parts[3]
      const count = Number.parseInt(parts[4], 10)

      if (
        !baseIP ||
        !Number.isFinite(count) ||
        count <= 0
      ) {
        continue
      }

      // APNIC gives the number of addresses.
      // Convert it into CIDR prefix length.
      const bits = 32 - Math.log2(count)

      if (!Number.isInteger(bits)) {
        continue
      }

      if (bits < 0 || bits > 32) {
        continue
      }

      const prefix = `${baseIP}/${bits}`

      // Keep an explicitly known mapping if we already have one.
      if (map.has(prefix)) {
        continue
      }

      // Try to associate the APNIC block with one of our known
      // Indian ASN prefixes.
      const match = INDIAN_ASNS.find(asn =>
        asn?.prefixes?.some(knownPrefix => {
          const knownBase =
            knownPrefix
              .split('/')[0]
              .split('.')
              .slice(0, 2)
              .join('.')

          const apnicBase =
            baseIP
              .split('.')
              .slice(0, 2)
              .join('.')

          return knownBase === apnicBase
        })
      )

      if (match) {
        map.set(prefix, match)
      } else {
        // CRITICAL:
        //
        // Do NOT use:
        //
        //   match ?? INDIAN_ASNS[0]
        //
        // because that causes every unknown Indian network to appear
        // as Reliance Jio.
        map.set(
          prefix,
          createUnknownASN(
            prefix,
            'Indian Network'
          )
        )
      }

      matched++
    }

    prefixMap = map

    onProgress?.(
      `Loaded ${map.size} Indian prefixes ` +
      `(${matched} from APNIC live data)`
    )

    console.log(
      `[SnapShield APNIC] Loaded ${map.size} Indian prefixes ` +
      `(${matched} enriched from APNIC)`
    )
  } catch (error) {
    console.warn(
      '[SnapShield APNIC] Using hardcoded fallback:',
      error?.message ?? error
    )

    prefixMap = buildFallbackMap()

    onProgress?.(
      `Using fallback database: ${prefixMap.size} prefixes`
    )
  }

  loaded = true
  loading = false
}

// ─────────────────────────────────────────────────────────────────────────────
// Prefix lookup
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Find the best ASN match for a prefix.
 *
 * Exact match wins first.
 * Otherwise the most-specific CIDR match wins.
 *
 * Returns:
 *   known ASN object
 *   unknown ASN object
 *   null when the prefix is not in our Indian database
 */
export function findIndianASNForPrefix(prefix) {
  if (!prefixMap || !prefix) {
    return null
  }

  // Fast exact lookup.
  if (prefixMap.has(prefix)) {
    return prefixMap.get(prefix)
  }

  const ip = prefix.split('/')[0]

  if (!ip) {
    return null
  }

  // Most-specific match wins.
  let bestMatch = null
  let bestBits = -1

  for (const [knownPrefix, asn] of prefixMap) {
    const bits = Number.parseInt(
      knownPrefix.split('/')[1] ?? '0',
      10
    )

    if (
      bits > bestBits &&
      ipInCIDR(ip, knownPrefix)
    ) {
      bestMatch = asn
      bestBits = bits
    }
  }

  return bestMatch
}

// ─────────────────────────────────────────────────────────────────────────────
// Known-vs-unknown helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true ONLY when we have a real ASN mapping.
 *
 * Unknown placeholders such as:
 *   AS-IN
 *   AS-IN-UNKNOWN
 *
 * are deliberately excluded.
 */
export function isIndianPrefix(prefix) {
  const result =
    findIndianASNForPrefix(prefix)

  if (!result) {
    return false
  }

  if (result.isUnknown) {
    return false
  }

  if (
    !result.asn ||
    result.asn === 'AS-IN' ||
    result.asn === 'AS-IN-UNKNOWN'
  ) {
    return false
  }

  return true
}

/**
 * Returns true when the prefix exists in the Indian prefix database,
 * even if its exact ASN is unknown.
 */
export function isIndianNetwork(prefix) {
  return findIndianASNForPrefix(prefix) !== null
}

/**
 * Convenience helper for UI/API code.
 */
export function isUnknownIndianPrefix(prefix) {
  const result =
    findIndianASNForPrefix(prefix)

  return Boolean(
    result?.isUnknown === true
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Status
// ─────────────────────────────────────────────────────────────────────────────

export function getAPNICStatus() {
  return {
    loaded,
    loading,
    prefixCount: prefixMap?.size ?? 0,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Optional cache reset
// ─────────────────────────────────────────────────────────────────────────────

export function clearASNResolutionCache() {
  asnResolutionCache.clear()
}
