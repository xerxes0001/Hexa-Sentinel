/**
 * Hexa Sentinel
 * RIPE RIS Live WebSocket
 *
 * Features:
 * - Monitors BGP announcements and withdrawals
 * - Matches prefixes against the Indian ASN database
 * - Detects origin-AS mismatches
 * - Detects suspicious AS-path behaviour
 * - Detects AS-path prepending and loops
 * - Parses BGP communities
 * - Calculates transparent confidence scores
 * - Automatically reconnects after connection failures
 *
 * NOTE:
 * RIS Live subscriptions are used for UPDATE messages. Prefix/ASN
 * filtering is performed locally against the Hexa Sentinel prefix database.
 */

import { findIndianASNForPrefix } from './apnic.js'
import { INDIAN_ASNS } from '../data/indianASNs.js'

const RIS_URL =
  'wss://ris-live.ripe.net/v1/ws/?client=hexasentinel-v1'

// ---------------------------------------------------------------------------
// Indian ASN lookup set
// ---------------------------------------------------------------------------

const INDIAN_ASN_NUMBERS = new Set(
  INDIAN_ASNS
    .map((a) => parseInt(String(a.asn).replace(/^AS/i, ''), 10))
    .filter(Number.isFinite)
)

// Real-world BGP paths can be fairly long.
// These values are intentionally conservative so normal routing is not
// incorrectly classified as malicious.
const NORMAL_PATH_MIN = 2
const NORMAL_PATH_MAX = 20

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

function scoreConfidenceBreakdown(entry, rpkiState) {
  const factors = [
    {
      label: 'Base score',
      points: 40,
    },
  ]

  let score = 40

  // RPKI state
  if (rpkiState === 'invalid') {
    factors.push({
      label: 'RPKI invalid (origin is not authorized)',
      points: 35,
    })

    score += 35
  }

  if (rpkiState === 'not-found') {
    factors.push({
      label: 'No ROA found (prefix is not RPKI protected)',
      points: 10,
    })

    score += 10
  }

  if (rpkiState === 'valid') {
    factors.push({
      label: 'RPKI valid (authorized origin)',
      points: -20,
    })

    score -= 20
  }

  // Path anomalies
  if (entry.pathAnomaly === 'PATH_TOO_SHORT') {
    factors.push({
      label: 'AS path suspiciously short',
      points: 25,
    })

    score += 25
  }

  if (entry.pathAnomaly === 'PATH_TOO_LONG') {
    factors.push({
      label: 'AS path unusually long',
      points: 15,
    })

    score += 15
  }

  // AS path prepending
  if (entry.prependCount > 0) {
    const points = Math.min(entry.prependCount * 8, 20)

    factors.push({
      label: `AS-path prepending ×${entry.prependCount}`,
      points,
    })

    score += points
  }

  // BGP communities
  if (entry.hasSuspiciousCommunity) {
    factors.push({
      label: 'Suspicious BGP community',
      points: 15,
    })

    score += 15
  }

  if (entry.hasBlackholeComm) {
    factors.push({
      label: 'Blackhole community detected',
      points: 20,
    })

    score += 20
  }

  // More-specific prefix
  const prefixBits = parseInt(
    entry.prefix?.split('/')[1] ?? '0',
    10
  )

  const expectedBits = parseInt(
    entry.matchedASN?.prefixes?.[0]?.split('/')[1] ?? '0',
    10
  )

  if (
    Number.isFinite(prefixBits) &&
    Number.isFinite(expectedBits) &&
    prefixBits > expectedBits + 2
  ) {
    factors.push({
      label: 'More-specific sub-prefix detected',
      points: 20,
    })

    score += 20
  }

  // Origin mismatch
  if (!entry.isExpectedOrigin) {
    factors.push({
      label: 'Origin AS does not match expected owner',
      points: 15,
    })

    score += 15
  }

  const total = Math.max(
    0,
    Math.min(100, score)
  )

  return {
    total,
    factors,
  }
}

function scoreConfidence(entry, rpkiState) {
  return scoreConfidenceBreakdown(entry, rpkiState).total
}

// ---------------------------------------------------------------------------
// Origin validation
// ---------------------------------------------------------------------------

export function computeIsExpectedOrigin(matchedASN, originAS) {
  if (!matchedASN || !originAS) {
    return false
  }

  // Unknown prefixes must not be treated as malicious merely because
  // there is no known ASN mapping.
  if (matchedASN.isUnknown === true) {
    return true
  }

  return (
    String(matchedASN.asn).toUpperCase() ===
    String(originAS).toUpperCase()
  )
}

// ---------------------------------------------------------------------------
// AS path analysis
// ---------------------------------------------------------------------------

function analyzeASPath(path) {
  if (!Array.isArray(path) || path.length === 0) {
    return {
      prependCount: 0,
      hasLoop: false,
      uniqueHops: 0,
    }
  }

  const counts = new Map()

  for (const asn of path) {
    const value = String(asn)

    counts.set(
      value,
      (counts.get(value) ?? 0) + 1
    )
  }

  let prependCount = 0

  for (const [, count] of counts) {
    if (count > 1) {
      prependCount += count - 1
    }
  }

  // Detect non-adjacent repetition.
  // Adjacent repeats are normally AS-path prepending and are therefore
  // not automatically treated as routing loops.
  let hasLoop = false

  for (let i = 0; i < path.length; i++) {
    const current = String(path[i])

    for (let j = 0; j < i; j++) {
      const previous = String(path[j])

      if (
        previous === current &&
        String(path[i - 1]) !== current
      ) {
        hasLoop = true
        break
      }
    }

    if (hasLoop) break
  }

  return {
    prependCount,
    hasLoop,
    uniqueHops: counts.size,
  }
}

// ---------------------------------------------------------------------------
// BGP community analysis
// ---------------------------------------------------------------------------

const BLACKHOLE_COMMUNITIES = [
  '65535:666',
  '65535:0',
]

const SUSPICIOUS_COMMUNITIES = [
  '0:0',
  '65535:65281',
]

function normalizeCommunity(community) {
  if (Array.isArray(community)) {
    return community.join(':')
  }

  return String(community)
}

function parseCommunities(communities) {
  if (
    !Array.isArray(communities) ||
    communities.length === 0
  ) {
    return {
      hasBlackholeComm: false,
      hasSuspiciousCommunity: false,
      raw: [],
    }
  }

  const raw = communities.map(normalizeCommunity)

  return {
    hasBlackholeComm: raw.some((community) =>
      BLACKHOLE_COMMUNITIES.includes(community)
    ),

    hasSuspiciousCommunity: raw.some((community) =>
      SUSPICIOUS_COMMUNITIES.includes(community)
    ),

    raw,
  }
}

// ---------------------------------------------------------------------------
// Path anomaly detection
// ---------------------------------------------------------------------------

function detectPathAnomaly(path) {
  if (!Array.isArray(path) || path.length === 0) {
    return null
  }

  if (path.length < NORMAL_PATH_MIN) {
    return 'PATH_TOO_SHORT'
  }

  if (path.length > NORMAL_PATH_MAX) {
    return 'PATH_TOO_LONG'
  }

  return null
}

// ---------------------------------------------------------------------------
// RIS message parser
// ---------------------------------------------------------------------------

function parseRISMessage(raw) {
  try {
    const message =
      typeof raw === 'string'
        ? JSON.parse(raw)
        : raw

    if (message?.type !== 'ris_message') {
      return null
    }

    const data = message.data

    if (!data) {
      return null
    }

    const path = Array.isArray(data.path)
      ? data.path
      : []

    const peer = data.peer ?? 'unknown'

    const peerASN = data.peer_asn
      ? `AS${data.peer_asn}`
      : 'unknown'

    const host =
      data.host ??
      message.host ??
      peer

    const timestamp = data.timestamp
      ? new Date(data.timestamp * 1000)
      : new Date()

    const originAS =
      path.length > 0
        ? `AS${path[path.length - 1]}`
        : peerASN

    const results = []

    const pathAnalysis = analyzeASPath(path)

    const communityInfo =
      parseCommunities(data.communities)

    const pathAnomaly =
      detectPathAnomaly(path)

    // -----------------------------------------------------------------------
    // Announcements
    // -----------------------------------------------------------------------

    if (
      data.type === 'UPDATE' &&
      Array.isArray(data.announcements) &&
      data.announcements.length > 0
    ) {
      for (const announcement of data.announcements) {
        const prefixes =
          Array.isArray(announcement.prefixes)
            ? announcement.prefixes
            : []

        for (const prefix of prefixes) {
          const matchedASN =
            findIndianASNForPrefix(prefix)

          // Ignore non-Indian prefixes.
          if (!matchedASN) {
            continue
          }

          const isExpectedOrigin =
            computeIsExpectedOrigin(
              matchedASN,
              originAS
            )

          // We deliberately require stronger evidence before marking an
          // announcement suspicious.
          const isSuspicious =
            !isExpectedOrigin ||
            communityInfo.hasBlackholeComm ||
            communityInfo.hasSuspiciousCommunity ||
            pathAnalysis.prependCount > 4 ||
            pathAnalysis.hasLoop ||
            (
              pathAnomaly === 'PATH_TOO_SHORT' &&
              !isExpectedOrigin
            )

          const scoringEntry = {
            pathAnomaly,
            prependCount:
              pathAnalysis.prependCount,

            isExpectedOrigin,

            prefix,
            matchedASN,

            hasSuspiciousCommunity:
              communityInfo.hasSuspiciousCommunity,

            hasBlackholeComm:
              communityInfo.hasBlackholeComm,
          }

          const confidence =
            scoreConfidence(
              scoringEntry,
              null
            )

          const confidenceBreakdown =
            scoreConfidenceBreakdown(
              scoringEntry,
              null
            )

          let text

          if (!isExpectedOrigin) {
            text =
              `ANOMALY: ${prefix} via ${originAS} — ` +
              `expected ${matchedASN.asn}`
          } else if (
            pathAnomaly &&
            pathAnomaly !== 'PATH_TOO_SHORT'
          ) {
            text =
              `PATH ANOMALY: ${matchedASN.asn} ` +
              `${prefix} — ${path.length} hops ` +
              `(${pathAnomaly})`
          } else if (
            communityInfo.hasBlackholeComm
          ) {
            text =
              `BLACKHOLE: ${matchedASN.asn} ` +
              `${prefix} via ${peerASN}`
          } else {
            text =
              `BGP UPDATE: ${matchedASN.asn} ` +
              `announces ${prefix} — ` +
              `${path.length} hops`
          }

          results.push({
            eventType: 'ANNOUNCEMENT',

            prefix,
            path,
            peer,
            peerASN,
            originAS,
            host,
            matchedASN,

            isExpectedOrigin,
            isSuspicious,

            pathAnomaly,
            timestamp,

            // AS-path information
            prependCount:
              pathAnalysis.prependCount,

            hasLoop:
              pathAnalysis.hasLoop,

            uniqueHops:
              pathAnalysis.uniqueHops,

            // Community information
            hasBlackholeComm:
              communityInfo.hasBlackholeComm,

            hasSuspiciousCommunity:
              communityInfo.hasSuspiciousCommunity,

            communities:
              communityInfo.raw,

            // Network information
            nextHop:
              data.next_hop ??
              announcement.next_hop ??
              null,

            peerIP:
              data.peer ?? null,

            // Detection score
            confidence,

            rawConfidence: confidence,

            confidenceBreakdown:
              confidenceBreakdown.factors,

            rawConfidenceBreakdown:
              confidenceBreakdown.factors,

            text,
          })
        }
      }
    }

    // -----------------------------------------------------------------------
    // Withdrawals
    // -----------------------------------------------------------------------

    if (
      data.type === 'UPDATE' &&
      Array.isArray(data.withdrawals) &&
      data.withdrawals.length > 0
    ) {
      for (const prefix of data.withdrawals) {
        const matchedASN =
          findIndianASNForPrefix(prefix)

        if (!matchedASN) {
          continue
        }

        results.push({
          eventType: 'WITHDRAWAL',

          prefix,
          path: [],

          peer,
          peerASN,
          originAS,
          host,

          matchedASN,

          isExpectedOrigin: true,
          isSuspicious: false,

          pathAnomaly: null,
          timestamp,

          prependCount: 0,
          hasLoop: false,
          uniqueHops: 0,

          hasBlackholeComm: false,
          hasSuspiciousCommunity: false,

          communities: [],

          confidence: 0,

          text:
            `BGP WITHDRAW: ${matchedASN.asn} ` +
            `withdrew ${prefix} via ${peerASN}`,

          isWithdrawal: true,
        })
      }
    }

    return results.length > 0
      ? results
      : null

  } catch (error) {
    console.warn(
      '[Hexa Sentinel] Failed to parse RIS message:',
      error
    )

    return null
  }
}

// ---------------------------------------------------------------------------
// RIPE RIS WebSocket connection
// ---------------------------------------------------------------------------

export class RIPERISConnection {
  constructor({
    onEntry,
    onWithdrawal,
    onStatusChange,
    onError,
  }) {
    this.onEntry =
      onEntry ?? (() => {})

    this.onWithdrawal =
      onWithdrawal ?? (() => {})

    this.onStatusChange =
      onStatusChange ?? (() => {})

    this.onError =
      onError ?? (() => {})

    this.ws = null

    this.reconnectTimer = null

    this.reconnectDelay = 3000

    this.maxDelay = 30000

    this.shouldReconnect = true

    this.messageCount = 0

    this.indianCount = 0
  }

  connect() {
    if (
      this.ws?.readyState ===
      WebSocket.OPEN
    ) {
      return
    }

    this.shouldReconnect = true

    this._connect()
  }

  _connect() {
    this.onStatusChange('connecting')

    try {
      this.ws = new WebSocket(RIS_URL)

    } catch (error) {
      this.onStatusChange('error')

      this.onError(
        `WebSocket creation failed: ${error.message}`
      )

      this._scheduleReconnect()

      return
    }

    this.ws.onopen = () => {
      this.onStatusChange('connected')

      this.reconnectDelay = 3000

      /*
       * RIS Live UPDATE subscription.
       *
       * The complete Indian ASN/prefix filtering is performed locally
       * because the application needs to validate the announcement
       * against its own prefix database.
       */
      try {
        this.ws.send(
          JSON.stringify({
            type: 'ris_subscribe',

            data: {
              type: 'UPDATE',

              moreSpecific: true,
            },
          })
        )
      } catch (error) {
        this.onError(
          `RIS subscription failed: ${error.message}`
        )
      }
    }

    this.ws.onmessage = (event) => {
      this.messageCount++

      const entries =
        parseRISMessage(event.data)

      if (!entries) {
        return
      }

      for (const entry of entries) {
        this.indianCount++

        if (entry.isWithdrawal) {
          this.onWithdrawal(entry)
        } else {
          this.onEntry(entry)
        }
      }
    }

    this.ws.onerror = () => {
      this.onStatusChange('error')

      this.onError(
        'RIS WebSocket error. Retrying...'
      )
    }

    this.ws.onclose = () => {
      this.ws = null

      if (this.shouldReconnect) {
        this.onStatusChange('disconnected')

        this._scheduleReconnect()
      }
    }
  }

  _scheduleReconnect() {
    if (!this.shouldReconnect) {
      return
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
    }

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null

      if (this.shouldReconnect) {
        this._connect()
      }
    }, this.reconnectDelay)

    this.reconnectDelay =
      Math.min(
        this.reconnectDelay * 1.5,
        this.maxDelay
      )
  }

  disconnect() {
    this.shouldReconnect = false

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)

      this.reconnectTimer = null
    }

    if (this.ws) {
      try {
        this.ws.close()
      } catch {
        // Ignore close errors.
      }

      this.ws = null
    }

    this.onStatusChange('disconnected')
  }
}

// ---------------------------------------------------------------------------
// Public exports
// ---------------------------------------------------------------------------

export {
  scoreConfidence,
  scoreConfidenceBreakdown,
  parseRISMessage,
  analyzeASPath,
  parseCommunities,
  detectPathAnomaly,
}
