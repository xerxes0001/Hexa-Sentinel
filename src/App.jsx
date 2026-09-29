import { useEffect, useState, lazy, Suspense } from 'react'
import { useSHYENStore } from './store/useSHYENStore.js'

import {
  RIPERISConnection,
  scoreConfidence,
  scoreConfidenceBreakdown
} from './api/ripeRIS.js'

import {
  getDecision,
  connectThreatStream,
  checkHealth
} from './api/snapshieldAPI.js'

import { preCheckRPKI } from './api/rpkiCheck.js'
import {
  lookupASCountry,
  prewarmASCache
} from './api/asLookup.js'

import {
  loadAPNICData,
  getAPNICStatus,
  resolveRealASN
} from './api/apnic.js'

import {
  recordAttack,
  escalateSeverity
} from './engine/attackMemory.js'

import {
  getMitigationDelay,
  executeDeterministicMitigation,
  buildDeterministicSummary
} from './engine/autonomousActions.js'

import { generateCountermeasures } from './engine/countermeasureGenerator.js'

import { checkCoordinatedAttack } from './utils/certMonitor.js'

import {
  DEMO_INCIDENTS,
  DEMO_INCIDENT_INTERVAL_MS
} from './data/demoScript.js'

import { getSeverity } from './engine/severityEngine.js'
import { hostToVantage } from './data/vantagePoints.js'
import { usePageTitle } from './hooks/usePageTitle.js'
import { SEVERITY_ORDER } from './utils/severity.js'

import TopNav from './components/layout/TopNav.jsx'
import BGPTicker from './components/layout/BGPTicker.jsx'
import StatsBar from './components/layout/StatsBar.jsx'
import WhatHappened from './components/layout/WhatHappened.jsx'
import Footer from './components/layout/Footer.jsx'
import OperationalTimeline from './components/layout/OperationalTimeline.jsx'
import IncidentList from './components/incidents/IncidentList.jsx'
import AttackHeatmap from './components/incidents/AttackHeatmap.jsx'
import ASNHealthGrid from './components/asns/ASNHealthGrid.jsx'
import DetailPanel from './components/detail/DetailPanel.jsx'
import AINotification from './components/shared/AINotification.jsx'
import PanelErrorBoundary from './components/shared/PanelErrorBoundary.jsx'
import ThreatMap from './components/map/ThreatMap.jsx'
import SnapShieldPanel from './components/panels/SnapShieldPanel.jsx'
import NetworkGraph from './components/panels/NetworkGraph.jsx'

const Globe3D = lazy(() =>
  import('./components/map/Globe3D.jsx')
)

const BreachSimulator = lazy(() =>
  import('./components/breach/BreachSimulator.jsx')
)

const CountryHistoryPage = lazy(() =>
  import('./components/pages/CountryHistoryPage.jsx')
)

function PanelFallback() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100%',
        minHeight: 200,
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--text-muted)',
        letterSpacing: 1,
      }}
    >
      LOADING…
    </div>
  )
}

let incidentIdCounter = 1000

// -----------------------------------------------------------------------------
// Incident protection
// -----------------------------------------------------------------------------

const PER_PREFIX_COOLDOWN = 10000

const MIN_CONFIDENCE_TO_INCIDENT = 85

const VANTAGE_CORROBORATION_REQUIRED = 2

const NPU_THREAT_THRESHOLD = 0.85

const NPU_CRITICAL_THRESHOLD = 0.92

const NPU_INCIDENT_COOLDOWN = 15000

const prefixCooldowns = new Map()

const activeIncidentKeys = new Map()

const anomalyVantagePoints = new Map()

const recentTickerTexts = new Map()

const npuIncidentCooldowns = new Map()

const TICKER_DEDUPE_MS = 45000


// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------

function normalizeNPUScore(event) {
  const score =
    Number(
      event?.score ??
      event?.anomaly_score ??
      event?.confidence ??
      0
    )

  if (!Number.isFinite(score)) return 0

  return Math.max(0, Math.min(1, score))
}


function getNPUSeverity(score) {
  if (score >= NPU_CRITICAL_THRESHOLD) {
    return 'CRITICAL'
  }

  if (score >= 0.85) {
    return 'HIGH'
  }

  if (score >= 0.70) {
    return 'MEDIUM'
  }

  return 'LOW'
}


function getNPUAttackType(event) {
  const type =
    event?.attack_type ??
    event?.attackType ??
    event?.classification ??
    event?.label ??
    event?.threat_type

  if (typeof type === 'string' && type.length > 0) {
    return type.toUpperCase().replace(/\s+/g, '_')
  }

  return 'NETWORK_ANOMALY'
}


function getNPUAttacker(event) {
  const asn =
    event?.attacker_asn ??
    event?.origin_as ??
    event?.originAS ??
    event?.asn ??
    'UNKNOWN'

  const country =
    event?.country ??
    event?.attacker_country ??
    '??'

  return {
    asn: String(asn),
    name: String(asn),
    country: country || '??',
  }
}


function getNPUVictim(event) {
  const prefix =
    event?.prefix ??
    event?.destination_prefix ??
    event?.dst_prefix ??
    'UNKNOWN'

  const asn =
    event?.victim_asn ??
    event?.destination_asn ??
    'UNKNOWN'

  const name =
    event?.victim_name ??
    event?.organization ??
    `Protected prefix ${prefix}`

  return {
    asn: String(asn),
    name: String(name),
    sector: event?.sector ?? 'Unknown',
    prefixes: prefix !== 'UNKNOWN' ? [prefix] : [],
    isUnknown: asn === 'UNKNOWN',
  }
}


function getEventPrefix(event) {
  return (
    event?.prefix ??
    event?.destination_prefix ??
    event?.dst_prefix ??
    event?.victim_prefix ??
    'UNKNOWN'
  )
}


// -----------------------------------------------------------------------------
// Central incident pipeline
// -----------------------------------------------------------------------------

async function enrichAndAdd(incident) {
  const store = useSHYENStore.getState()

  if (store.isPaused) {
    return null
  }

  const memory = recordAttack(incident)

  const enriched = {
    ...incident,

    severity: escalateSeverity(
      incident.severity,
      memory.isRepeat
    ),

    isRepeatAttacker: memory.isRepeat,

    repeatCount: memory.attackCount,

    deterministicSummary:
      buildDeterministicSummary(incident),
  }

  // ---------------------------------------------------------------------------
  // Add incident immediately
  // ---------------------------------------------------------------------------

  store.addIncident(enriched)

  // ---------------------------------------------------------------------------
  // Generate countermeasures
  // ---------------------------------------------------------------------------

  const countermeasures =
    generateCountermeasures(enriched)

  useSHYENStore.setState(state => ({
    incidents: state.incidents.map(item =>
      item.id === enriched.id
        ? {
            ...item,
            countermeasures,
            countermeasuresReady: true,
          }
        : item
    ),

    activityLog: [
      ...state.activityLog,

      {
        id: Date.now(),

        level: 'SUCCESS',

        message: enriched.isSimulated
          ? `[DEMO] COUNTERMEASURES GENERATED · RPKI ROA + RTBH + Flowspec · ${enriched.victim?.name}`
          : `COUNTERMEASURES GENERATED · RPKI ROA + RTBH + Flowspec · ${enriched.victim?.name} · pending NOC authorization`,

        incidentId: enriched.id,

        timestamp: new Date().toISOString(),
      },
    ].slice(-80),
  }))

  // ---------------------------------------------------------------------------
  // Demo mitigation
  // ---------------------------------------------------------------------------

  if (enriched.isSimulated) {
    const delay = getMitigationDelay(
      enriched.severity,
      enriched.isRepeatAttacker
    )

    setTimeout(() => {
      const freshStore =
        useSHYENStore.getState()

      const current =
        freshStore.incidents.find(
          item => item.id === enriched.id
        )

      if (!current || current.status === 'MITIGATED') {
        return
      }

      const {
        updated,
        actions
      } = executeDeterministicMitigation(current)

      useSHYENStore.setState(state => ({
        incidents: state.incidents.map(item =>
          item.id === enriched.id
            ? updated
            : item
        ),

        activityLog: [
          ...state.activityLog,

          {
            id: Date.now(),

            level: 'SUCCESS',

            message:
              `[DEMO] SIMULATED MITIGATION ` +
              `[${actions.map(a => a.label).join(' + ')}] · ` +
              `${enriched.victim?.name} · ` +
              `TTM ${(delay / 1000).toFixed(1)}s`,

            incidentId: enriched.id,

            timestamp: new Date().toISOString(),
          },
        ].slice(-80),
      }))
    }, delay)
  }

  // ---------------------------------------------------------------------------
  // RPKI validation
  // ---------------------------------------------------------------------------

  if (
    !enriched.isSimulated &&
    enriched.victim?.asn &&
    !String(enriched.victim.asn).includes('UNKNOWN') &&
    !enriched.victim?.isUnknown
  ) {
    preCheckRPKI(enriched).then(rpki => {
      if (!rpki) return

      const state =
        useSHYENStore.getState()

      state.setIncidentRPKI(
        enriched.id,
        rpki
      )

      const label =
        rpki.valid
          ? 'RPKI VALID'
          : rpki.invalid
            ? 'RPKI INVALID — vulnerable'
            : 'RPKI UNKNOWN'

      state.addActivityLog?.(
        rpki.valid ? 'SUCCESS' : 'INFO',
        `RPKI check (${enriched.prefix}): ${label}`,
        enriched.id
      )

      const rpkiState =
        rpki.invalid
          ? 'invalid'
          : rpki.valid
            ? 'valid'
            : 'not-found'

      const vantageBonus =
        Math.min(
          (enriched.confirmedPoints?.length ?? 1) - 1,
          4
        ) * 5

      const signals = {
        pathAnomaly: enriched.pathAnomaly,

        prependCount:
          enriched.prependCount ?? 0,

        isExpectedOrigin:
          enriched.victim?.asn ===
          enriched.attacker?.asn,

        prefix: enriched.prefix,

        matchedASN:
          enriched.victim,

        hasSuspiciousCommunity:
          enriched.hasSuspiciousCommunity ?? false,

        hasBlackholeComm:
          enriched.hasBlackholeComm ?? false,
      }

      const {
        total: baseScore,
        factors,
      } = scoreConfidenceBreakdown(
        signals,
        rpkiState
      )

      const breakdown =
        vantageBonus > 0
          ? [
              ...factors,
              {
                label:
                  `${enriched.confirmedPoints?.length ?? 1} vantage points confirmed`,
                points: vantageBonus,
              },
            ]
          : factors

      const updatedConf =
        Math.min(
          99,
          Math.round(
            baseScore + vantageBonus
          )
        )

      if (
        updatedConf !==
        enriched.confidence
      ) {
        useSHYENStore
          .getState()
          .setIncidentConfidence?.(
            enriched.id,
            updatedConf,
            breakdown
          )

        useSHYENStore
          .getState()
          .addActivityLog?.(
            'INFO',
            `Confidence updated: ${enriched.confidence}% → ${updatedConf}% (RPKI ${rpkiState})`,
            enriched.id
          )
      }
    })
  }

  // ---------------------------------------------------------------------------
  // Certificate Transparency correlation
  // ---------------------------------------------------------------------------

  if (!enriched.isSimulated) {
    checkCoordinatedAttack(enriched)
      .then(match => {
        if (!match) return

        useSHYENStore.setState(state => ({
          incidents: state.incidents.map(item =>
            item.id === enriched.id
              ? {
                  ...item,
                  coordinatedAttack: match,
                  severity: 'CRITICAL',
                }
              : item
          ),

          activityLog: [
            ...state.activityLog,

            {
              id: Date.now(),

              level: 'CRITICAL',

              message:
                `COORDINATED ATTACK — BGP hijack + suspicious TLS certificate on ` +
                `${match.domain} · ${enriched.victim?.name}`,

              incidentId: enriched.id,

              timestamp:
                new Date().toISOString(),
            },
          ].slice(-80),
        }))
      })
  }

  // ---------------------------------------------------------------------------
  // Attacker country
  // ---------------------------------------------------------------------------

  if (
    !enriched.isSimulated &&
    enriched.attacker?.country === '??'
  ) {
    lookupASCountry(
      enriched.attacker.asn
    ).then(result => {
      if (
        result?.country &&
        result.country !== 'XX'
      ) {
        const state =
          useSHYENStore.getState()

        state.setIncidentAttackerCountry(
          enriched.id,
          result.country
        )

        state.addActivityLog?.(
          'INFO',
          `Resolved attacker origin: ${enriched.attacker.asn} → ${result.country}`,
          enriched.id
        )
      }
    })
  }

  // ---------------------------------------------------------------------------
  // Victim ASN resolution
  // ---------------------------------------------------------------------------

  if (
    !enriched.isSimulated &&
    enriched.victim?.isUnknown &&
    enriched.prefix
  ) {
    resolveRealASN(
      enriched.prefix
    ).then(result => {
      if (!result) return

      const resolvedVictim = {
        ...enriched.victim,

        asn: result.asn,

        name:
          result.holder ??
          enriched.victim.name,

        isUnknown: false,
      }

      const state =
        useSHYENStore.getState()

      state.setIncidentVictim?.(
        enriched.id,
        resolvedVictim
      )

      state.addActivityLog?.(
        'INFO',
        `Resolved victim: ${enriched.prefix} → ${result.asn} (${result.holder})`,
        enriched.id
      )
    })
  }

  // ---------------------------------------------------------------------------
  // Llama AI analysis
  // ---------------------------------------------------------------------------

  if (!enriched.isSimulated) {
    getDecision(
      enriched,
      () =>
        useSHYENStore
          .getState()
          .markAIAnalyzing(enriched.id)
    )
      .then(decision => {
        if (!decision) return

        useSHYENStore
          .getState()
          .markAIDecided(
            enriched.id,
            decision
          )
      })
  }

  return enriched.id
}


// -----------------------------------------------------------------------------
// BGP attack type
// -----------------------------------------------------------------------------

function detectAttackType(entry) {
  if (
    entry.pathAnomaly ===
    'PATH_TOO_SHORT'
  ) {
    return 'ORIGIN_HIJACK'
  }

  if (
    entry.pathAnomaly ===
    'PATH_TOO_LONG'
  ) {
    return 'PATH_MANIPULATION'
  }

  const prefixBits =
    parseInt(
      entry.prefix?.split('/')[1] ?? '0'
    )

  const expectedBits =
    parseInt(
      entry
        .matchedASN
        ?.prefixes?.[0]
        ?.split('/')[1] ?? '0'
    )

  if (
    prefixBits >
    expectedBits + 4
  ) {
    return 'SUBPREFIX_HIJACK'
  }

  return 'ORIGIN_HIJACK'
}


// -----------------------------------------------------------------------------
// Recovery banner
// -----------------------------------------------------------------------------

function RecoveryBanner() {
  const recoveredSession =
    useSHYENStore(
      s => s.recoveredSession
    )

  const recoveredAt =
    useSHYENStore(
      s => s.recoveredAt
    )

  const recoveredUnfinishedCount =
    useSHYENStore(
      s => s.recoveredUnfinishedCount
    )

  const isPaused =
    useSHYENStore(
      s => s.isPaused
    )

  const incidentCount =
    useSHYENStore(
      s => s.incidents.length
    )

  const dismissRecoveryBanner =
    useSHYENStore(
      s => s.dismissRecoveryBanner
    )

  if (!recoveredSession) {
    return null
  }

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '8px 20px',

        background:
          'rgba(255,214,10,0.06)',

        borderBottom:
          '1px solid rgba(255,214,10,0.25)',

        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: '#ffd60a',

        flexShrink: 0,
        zIndex: 9,
      }}
    >
      <span>⟳</span>

      <span>
        Session recovered from persisted storage —
        {' '}
        {incidentCount}
        {' '}
        incident
        {incidentCount === 1 ? '' : 's'}
        {' '}
        restored

        {recoveredUnfinishedCount > 0 && (
          <>
            , {recoveredUnfinishedCount}
            {' '}
            still unmitigated
          </>
        )}

        {isPaused && (
          <>
            {' '}
            · session was paused, still paused
          </>
        )}

        {recoveredAt && (
          <>
            {' '}
            · recovered{' '}
            {new Date(
              recoveredAt
            )
              .toISOString()
              .slice(11, 19)}
            {' '}
            UTC
          </>
        )}
      </span>

      <button
        onClick={
          dismissRecoveryBanner
        }
        style={{
          marginLeft: 'auto',
          background: 'none',
          border: 'none',
          color: '#ffd60a',
          cursor: 'pointer',
          fontFamily:
            'var(--font-mono)',
          fontSize: 10,
          opacity: 0.7,
        }}
      >
        ✕ DISMISS
      </button>
    </div>
  )
}


// -----------------------------------------------------------------------------
// Main application
// -----------------------------------------------------------------------------

export default function App() {
  const incidents =
    useSHYENStore(
      s => s.incidents
    )

  const appMode =
    useSHYENStore(
      s => s.appMode
    )

  const selectedIncidentId =
    useSHYENStore(
      s => s.selectedIncidentId
    )

  const selectIncident =
    useSHYENStore(
      s => s.selectIncident
    )

  const addTickerEntry =
    useSHYENStore(
      s => s.addTickerEntry
    )

  const setSystemTime =
    useSHYENStore(
      s => s.setSystemTime
    )

  const setRisStatus =
    useSHYENStore(
      s => s.setRisStatus
    )

  const setRisError =
    useSHYENStore(
      s => s.setRisError
    )

  const incrementRisStats =
    useSHYENStore(
      s => s.incrementRisStats
    )

  const addVantageConfirmation =
    useSHYENStore(
      s => s.addVantageConfirmation
    )

  const setAPNICLoaded =
    useSHYENStore(
      s => s.setAPNICLoaded
    )

  const [showBreach, setShowBreach] =
    useState(false)

  const [apnicReady, setApnicReady] =
    useState(false)

  const [selectedCountry, setSelectedCountry] =
    useState(null)

  const [historyCountry, setHistoryCountry] =
    useState(null)

  const [view3D, setView3D] =
    useState(true)

  const [centerTab, setCenterTab] =
    useState('map')


  const selectedIncident =
    incidents.find(
      incident =>
        incident.id ===
        selectedIncidentId
    ) ?? null


  const filteredIncidents =
    selectedCountry
      ? incidents.filter(
          incident =>
            incident.attacker?.country ===
            selectedCountry
        )
      : incidents


  usePageTitle(
    incidents.filter(
      incident =>
        incident.status ===
        'DETECTED'
    ).length
  )


  // ---------------------------------------------------------------------------
  // Select first incident
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (
      !selectedIncidentId &&
      incidents.length > 0
    ) {
      selectIncident(
        incidents[0].id
      )
    }
  }, [
    incidents.length,
    selectedIncidentId,
    selectIncident
  ])


  // ---------------------------------------------------------------------------
  // Garbage collection
  // ---------------------------------------------------------------------------

  useEffect(() => {
    for (
      const [
        key,
        id
      ] of activeIncidentKeys.entries()
    ) {
      const incident =
        incidents.find(
          item => item.id === id
        )

      if (
        !incident ||
        incident.status ===
          'MITIGATED'
      ) {
        activeIncidentKeys.delete(key)
      }
    }
  }, [incidents])


  // ---------------------------------------------------------------------------
  // Close simulator in live mode
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (
      appMode !== 'demo' &&
      showBreach
    ) {
      setShowBreach(false)
    }
  }, [
    appMode,
    showBreach
  ])


  // ---------------------------------------------------------------------------
  // APNIC initialization
  // ---------------------------------------------------------------------------

  useEffect(() => {
    loadAPNICData()
      .then(() => {
        const {
          prefixCount
        } = getAPNICStatus()

        setAPNICLoaded(
          prefixCount
        )

        setApnicReady(true)
      })

    prewarmASCache()
  }, [])


  // ---------------------------------------------------------------------------
  // RIPE RIS live BGP feed
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (
      !apnicReady ||
      appMode !== 'live'
    ) {
      return
    }

    useSHYENStore
      .getState()
      .clearIncidents()

    const ris =
      new RIPERISConnection({
        onStatusChange:
          setRisStatus,

        onError: message => {
          setRisError(message)

          console.warn(
            '[SnapShield RIS]',
            message
          )
        },

        onEntry: entry => {
          const store =
            useSHYENStore
              .getState()

          const now =
            Date.now()

          const lastShown =
            recentTickerTexts.get(
              entry.text
            )

          const isDuplicateTicker =
            lastShown &&
            now - lastShown <
              TICKER_DEDUPE_MS

          if (
            !isDuplicateTicker
          ) {
            recentTickerTexts.set(
              entry.text,
              now
            )

            store.addTickerEntry({
              text: entry.text,
              suspicious:
                entry.isSuspicious,
              timestamp:
                entry.timestamp,
              realData: true,
            })
          }

          store.incrementRisStats()

          if (
            !entry.isSuspicious ||
            !entry.matchedASN
          ) {
            return
          }

          store.incrementRisIndianCount?.()

          const key =
            `${entry.prefix}|${entry.originAS}`

          // Existing incident
          if (
            activeIncidentKeys.has(
              key
            )
          ) {
            store.addVantageConfirmation(
              activeIncidentKeys.get(
                key
              ),
              hostToVantage(
                entry.host
              )
            )

            return
          }

          // Vantage corroboration
          const vantage =
            hostToVantage(
              entry.host
            )

          const seenFrom =
            anomalyVantagePoints.get(
              key
            ) ?? new Set()

          seenFrom.add(vantage)

          anomalyVantagePoints.set(
            key,
            seenFrom
          )

          if (
            seenFrom.size <
            VANTAGE_CORROBORATION_REQUIRED
          ) {
            return
          }

          // Confidence gate
          const rawConf =
            Math.min(
              99,
              entry.rawConfidence ??
                0
            )

          if (
            rawConf <
            MIN_CONFIDENCE_TO_INCIDENT
          ) {
            return
          }

          // Prefix cooldown
          const lastForPrefix =
            prefixCooldowns.get(
              key
            ) ?? 0

          if (
            now -
              lastForPrefix <
            PER_PREFIX_COOLDOWN
          ) {
            return
          }

          prefixCooldowns.set(
            key,
            now
          )

          const type =
            detectAttackType(
              entry
            )

          const newId =
            ++incidentIdCounter

          activeIncidentKeys.set(
            key,
            newId
          )

          enrichAndAdd({
            id: newId,

            type,

            severity:
              getSeverity(
                type,
                entry
                  .matchedASN
                  .sector
              ),

            victim:
              entry.matchedASN,

            attacker: {
              asn:
                entry.originAS,

              name:
                entry.originAS,

              country:
                '??',
            },

            prefix:
              entry.prefix,

            confirmedPoints: [
              hostToVantage(
                entry.host
              ),
            ],

            timestamp:
              entry.timestamp instanceof Date
                ? entry.timestamp.toISOString()
                : entry.timestamp,

            status:
              'DETECTED',

            rpkiPushed: false,
            ixpAlerted: false,
            forensicsReady: false,

            affectedIPs: (() => {
              const bits =
                parseInt(
                  entry
                    .prefix
                    ?.split('/')[1] ??
                    '24'
                )

              return Math.pow(
                2,
                32 - bits
              )
            })(),

            confidence:
              Math.min(
                99,
                entry.rawConfidence ??
                  55
              ),

            isRealData:
              true,

            isSimulated:
              false,

            pathAnomaly:
              entry.pathAnomaly ??
              null,
          })
        },

        onWithdrawal: entry => {
          const store =
            useSHYENStore
              .getState()

          store.addTickerEntry({
            text:
              entry.text,

            suspicious:
              false,

            timestamp:
              entry.timestamp,

            realData:
              true,

            isWithdrawal:
              true,
          })

          store.incrementRisStats()
        },
      })

    ris.connect()

    return () => {
      ris.disconnect()
    }
  }, [
    apnicReady,
    appMode,
    setRisStatus,
    setRisError
  ])


  // ---------------------------------------------------------------------------
  // System clock
  // ---------------------------------------------------------------------------

  useEffect(() => {
    const timer =
      setInterval(
        () =>
          setSystemTime(
            new Date()
          ),
        1000
      )

    return () =>
      clearInterval(timer)
  }, [setSystemTime])


  // ---------------------------------------------------------------------------
  // Session checkpoints
  // ---------------------------------------------------------------------------

  useEffect(() => {
    const CHECKPOINT_INTERVAL_MS =
      120000

    const timer =
      setInterval(
        () =>
          useSHYENStore
            .getState()
            .recordCheckpoint(
              'interval'
            ),
        CHECKPOINT_INTERVAL_MS
      )

    return () =>
      clearInterval(timer)
  }, [])


  // ---------------------------------------------------------------------------
  // Breach simulator keyboard shortcut
  // ---------------------------------------------------------------------------

  useEffect(() => {
    const handleKeyDown =
      event => {
        if (
          (event.key === 'b' ||
            event.key === 'B') &&
          event.target.tagName !==
            'INPUT' &&
          useSHYENStore
            .getState()
            .appMode ===
            'demo'
        ) {
          setShowBreach(true)
        }
      }

    window.addEventListener(
      'keydown',
      handleKeyDown
    )

    return () =>
      window.removeEventListener(
        'keydown',
        handleKeyDown
      )
  }, [])


  // ===========================================================================
  // NEW: SnapShield ONNX/NPU threat stream
  // ===========================================================================
  //
  // Backend pipeline:
  //
  // Scapy
  //   ↓
  // Feature extraction
  //   ↓
  // anomaly_classifier.onnx
  //   ↓
  // Qualcomm QNN / Hexagon NPU
  //   ↓
  // Llama analysis
  //   ↓
  // FastAPI WebSocket
  //   ↓
  // THIS BLOCK
  //
  // ===========================================================================
  useEffect(() => {
    const connection =
      connectThreatStream(
        event => {
          if (!event) {
            return
          }

          // Ignore heartbeat/pong packets
          if (
            event.type ===
              'heartbeat' ||
            event.type ===
              'pong'
          ) {
            return
          }

          const score =
            normalizeNPUScore(
              event
            )

          // Always expose meaningful backend events in the timeline
          if (
            score >= 0.70
          ) {
            const store =
              useSHYENStore
                .getState()

            const severity =
              getNPUSeverity(
                score
              )

            const report =
              event.report ??
              event.message ??
              event.reason ??
              'On-device anomaly detected'

            store.addActivityLog?.(
              severity === 'CRITICAL'
                ? 'CRITICAL'
                : 'WARNING',

              `[SnapShield ONNX/NPU] ` +
              `score=${score.toFixed(3)} · ` +
              `${report
                .split('\n')[0]
                .slice(0, 120)}`
            )
          }

          // ---------------------------------------------------------------
          // Only high-confidence NPU classifications become incidents
          // ---------------------------------------------------------------

          if (
            score <
            NPU_THREAT_THRESHOLD
          ) {
            return
          }

          const prefix =
            getEventPrefix(
              event
            )

          const attacker =
            getNPUAttacker(
              event
            )

          const victim =
            getNPUVictim(
              event
            )

          const cooldownKey =
            `${prefix}|${attacker.asn}`

          const now =
            Date.now()

          const lastIncident =
            npuIncidentCooldowns.get(
              cooldownKey
            ) ?? 0

          if (
            now -
              lastIncident <
            NPU_INCIDENT_COOLDOWN
          ) {
            return
          }

          npuIncidentCooldowns.set(
            cooldownKey,
            now
          )

          const severity =
            getNPUSeverity(
              score
            )

          const attackType =
            getNPUAttackType(
              event
            )

          const id =
            ++incidentIdCounter

          const timestamp =
            event.timestamp ??
            new Date().toISOString()

          // ---------------------------------------------------------------
          // NPU-origin incident
          // ---------------------------------------------------------------

          const npuIncident = {
            id,

            type:
              attackType,

            severity,

            victim,

            attacker,

            prefix,

            confirmedPoints:
              event.vantage
                ? [event.vantage]
                : ['LOCAL-NPU'],

            timestamp,

            status:
              'DETECTED',

            rpkiPushed:
              false,

            ixpAlerted:
              false,

            forensicsReady:
              false,

            affectedIPs:
              event.affected_ips ??
              event.affectedIPs ??
              0,

            // ONNX score → dashboard confidence
            confidence:
              Math.round(
                score * 100
              ),

            // Critical provenance fields
            isRealData:
              true,

            isSimulated:
              false,

            source:
              'SNAPSHIELD_ONNX',

            detector:
              'ONNX_ANOMALY_CLASSIFIER',

            inferenceProvider:
              event.execution_provider ??
              event.provider ??
              'QNNExecutionProvider',

            npuScore:
              score,

            classifier:
              event.classifier ??
              'anomaly_classifier.onnx',

            classification:
              event.classification ??
              event.label ??
              attackType,

            modelVersion:
              event.model_version ??
              null,

            aiReport:
              event.report ??
              event.message ??
              null,

            pathAnomaly:
              event.pathAnomaly ??
              null,

            // Preserve raw backend payload for detail/debug views
            npuEvent:
              event,
          }

          enrichAndAdd(
            npuIncident
          )

          // Select the new NPU incident
          setTimeout(() => {
            useSHYENStore
              .getState()
              .selectIncident?.(
                id
              )
          }, 50)
        },

        status => {
          console.log(
            '[SnapShield NPU WS]',
            status
          )
        }
      )

    // Health check
    checkHealth()
      .then(healthy => {
        if (!healthy) {
          console.warn(
            '[SnapShield] Backend not reachable — start the Python server'
          )

          useSHYENStore
            .getState()
            .addActivityLog?.(
              'WARNING',
              '[SnapShield] Python NPU backend unavailable'
            )
        } else {
          useSHYENStore
            .getState()
            .addActivityLog?.(
              'SUCCESS',
              '[SnapShield] ONNX/NPU backend connected'
            )
        }
      })

    return () => {
      connection?.close?.()
    }
  }, [])


  // ===========================================================================
  // DEMO MODE
  // ===========================================================================

  useEffect(() => {
    if (
      appMode !== 'demo'
    ) {
      return
    }

    useSHYENStore
      .getState()
      .clearIncidents()

    useSHYENStore
      .getState()
      .setRisStatus(
        'connected'
      )

    let cancelled = false
    let index = 0

    function playNext() {
      if (
        cancelled ||
        index >=
          DEMO_INCIDENTS.length
      ) {
        return
      }

      if (
        useSHYENStore
          .getState()
          .isPaused
      ) {
        setTimeout(
          playNext,
          1000
        )

        return
      }

      const script =
        DEMO_INCIDENTS[index]

      const incident = {
        ...script,

        id:
          ++incidentIdCounter,

        timestamp:
          new Date().toISOString(),

        isRealData:
          false,

        isSimulated:
          true,

        isDemoSession:
          true,

        status:
          'DETECTED',

        rpkiPushed:
          false,

        ixpAlerted:
          false,

        forensicsReady:
          false,
      }

      enrichAndAdd(
        incident
      )

      if (
        index === 0
      ) {
        setTimeout(
          () =>
            selectIncident(
              incident.id
            ),
          150
        )
      }

      index++

      if (
        index <
        DEMO_INCIDENTS.length
      ) {
        setTimeout(
          playNext,
          DEMO_INCIDENT_INTERVAL_MS
        )
      }
    }

    const timer =
      setTimeout(
        playNext,
        800
      )

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [
    appMode,
    selectIncident
  ])


  // ===========================================================================
  // Breach simulator
  // ===========================================================================

  function onBreachIncident(
    incident
  ) {
    if (
      useSHYENStore
        .getState()
        .appMode !==
      'demo'
    ) {
      console.warn(
        '[SnapShield] Blocked simulated incident in Live Mode'
      )

      return
    }

    const simulated = {
      ...incident,

      id:
        ++incidentIdCounter,

      isRealData:
        false,

      isSimulated:
        true,

      status:
        'DETECTED',

      rpkiPushed:
        false,

      ixpAlerted:
        false,

      forensicsReady:
        false,
    }

    enrichAndAdd(
      simulated
    )

    setTimeout(
      () =>
        selectIncident(
          simulated.id
        ),
      100
    )
  }


  // ===========================================================================
  // UI
  // ===========================================================================

  return (
    <div
      style={{
        height: '100vh',

        display: 'flex',
        flexDirection: 'column',

        position: 'relative',

        overflow: 'hidden',

        background:
          `radial-gradient(
            ellipse at 20% 50%,
            rgba(0,255,136,0.04) 0%,
            transparent 60%
          ),
          radial-gradient(
            ellipse at 80% 20%,
            rgba(255,45,85,0.05) 0%,
            transparent 50%
          ),
          #060a0f`,
      }}
    >

      <div
        style={{
          position: 'fixed',
          inset: 0,

          opacity: 0.05,

          pointerEvents: 'none',

          zIndex: 0,

          backgroundImage:
            `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='40' height='40'%3E%3Cpath d='M 40 0 L 0 0 0 40' fill='none' stroke='%2300ff88' stroke-width='0.5'/%3E%3C/svg%3E")`,
        }}
      />

      <TopNav
        onBreachClick={() =>
          setShowBreach(true)
        }
      />

      <RecoveryBanner />

      <BGPTicker />

      <StatsBar />

      <WhatHappened />


      <main
        style={{
          flex: 1,

          display: 'grid',

          gridTemplateColumns:
            '330px 1fr 360px',

          overflow: 'hidden',

          position: 'relative',

          zIndex: 5,
        }}
      >

        {/* LEFT */}

        <div
          style={{
            borderRight:
              '1px solid var(--border-subtle)',

            overflow: 'hidden',

            display: 'flex',
            flexDirection: 'column',
          }}
        >

          <div
            style={{
              flex: '1 1 60%',

              minHeight: 0,

              borderBottom:
                '1px solid var(--border-subtle)',

              overflow: 'hidden',

              display: 'flex',
              flexDirection: 'column',
            }}
          >

            <div
              style={{
                padding:
                  '10px 10px 0',

                display: 'flex',

                alignItems:
                  'center',

                justifyContent:
                  'space-between',
              }}
            >

              <div
                style={{
                  fontFamily:
                    'var(--font-display)',

                  fontSize: 12,

                  fontWeight: 700,
                }}
              >
                LIVE THREAT FEED
              </div>

              {selectedCountry && (
                <button
                  onClick={() =>
                    setSelectedCountry(
                      null
                    )
                  }

                  style={{
                    fontFamily:
                      'var(--font-mono)',

                    fontSize: 8,

                    color:
                      'var(--accent-red)',

                    background:
                      'rgba(255,45,85,0.08)',

                    border:
                      '1px solid rgba(255,45,85,0.25)',

                    borderRadius: 3,

                    padding:
                      '2px 8px',

                    cursor: 'pointer',

                    letterSpacing: 1,
                  }}
                >
                  {selectedCountry} ✕
                </button>
              )}

            </div>

            <IncidentList
              filteredIncidents={
                filteredIncidents
              }
            />

          </div>


          <div
            style={{
              flex:
                '0 0 auto',

              overflowY:
                'auto',

              display:
                'flex',

              flexDirection:
                'column',
            }}
          >

            <div
              style={{
                maxHeight:
                  '30%',

                overflowY:
                  'auto',
              }}
            >
              <AttackHeatmap />
            </div>

            <div
              style={{
                flexShrink: 0,

                borderTop:
                  '1px solid var(--border-subtle)',
              }}
            >
              <SnapShieldPanel
                compact
              />
            </div>

          </div>

        </div>


        {/* CENTER */}

        <div
          style={{
            overflowY: 'auto',

            borderRight:
              '1px solid var(--border-subtle)',

            display: 'flex',
            flexDirection: 'column',
          }}
        >

          <div
            style={{
              padding: 12,
            }}
          >

            <div
              style={{
                background:
                  'rgba(6,10,15,0.9)',

                border:
                  '1px solid var(--border-subtle)',

                borderRadius: 6,

                overflow: 'hidden',
              }}
            >

              <div
                style={{
                  padding:
                    '10px 16px',

                  borderBottom:
                    '1px solid var(--border-subtle)',

                  display: 'flex',

                  alignItems:
                    'center',

                  justifyContent:
                    'space-between',
                }}
              >

                <div>

                  <div
                    style={{
                      fontFamily:
                        'var(--font-display)',

                      fontSize: 13,

                      fontWeight: 700,
                    }}
                  >
                    {view3D
                      ? 'GLOBAL BGP THREAT GLOBE'
                      : 'GLOBAL BGP THREAT MAP'}
                  </div>

                  <div
                    style={{
                      fontFamily:
                        'var(--font-mono)',

                      fontSize: 8,

                      color:
                        'var(--text-muted)',

                      marginTop: 2,
                    }}
                  >
                    {view3D
                      ? 'Drag to rotate · click a marker for recent attacks & full history'
                      : 'Live attack visualization · click a node to filter incidents'}
                  </div>

                </div>


                <div
                  style={{
                    display: 'flex',
                    gap: 4,
                    flexShrink: 0,
                  }}
                >

                  {[
                    {
                      key: true,
                      label: '🌐 3D',
                    },

                    {
                      key: false,
                      label: '🗺 2D',
                    },
                  ].map(option => (
                    <button
                      key={
                        String(
                          option.key
                        )
                      }

                      onClick={() =>
                        setView3D(
                          option.key
                        )
                      }

                      style={{
                        fontFamily:
                          'var(--font-mono)',

                        fontSize: 9,

                        fontWeight: 700,

                        letterSpacing:
                          '0.05em',

                        padding:
                          '4px 10px',

                        borderRadius: 3,

                        cursor:
                          'pointer',

                        background:
                          view3D ===
                          option.key
                            ? 'var(--accent-green)'
                            : 'rgba(255,255,255,0.03)',

                        border:
                          `1px solid ${
                            view3D ===
                            option.key
                              ? 'var(--accent-green)'
                              : 'var(--border-subtle)'
                          }`,

                        color:
                          view3D ===
                          option.key
                            ? '#000'
                            : 'var(--text-muted)',
                      }}
                    >
                      {option.label}
                    </button>
                  ))}

                </div>

              </div>


              {view3D ? (
                <Suspense
                  fallback={
                    <PanelFallback />
                  }
                >
                  <Globe3D
                    onViewHistory={
                      setHistoryCountry
                    }

                    onCountryClick={
                      setSelectedCountry
                    }
                  />
                </Suspense>
              ) : (
                <>
                  <div
                    style={{
                      display: 'flex',
                      borderBottom:
                        '1px solid var(--border-subtle)',
                    }}
                  >

                    {[
                      [
                        'map',
                        '🗺 BGP MAP',
                      ],

                      [
                        'graph',
                        '📡 NETWORK GRAPH',
                      ],
                    ].map(
                      ([id, label]) => (
                        <button
                          key={id}

                          onClick={() =>
                            setCenterTab(
                              id
                            )
                          }

                          style={{
                            fontFamily:
                              'var(--font-mono)',

                            fontSize: 9,

                            fontWeight: 700,

                            padding:
                              '7px 18px',

                            background:
                              'transparent',

                            border:
                              'none',

                            cursor:
                              'pointer',

                            color:
                              centerTab ===
                              id
                                ? 'var(--accent-green,#10B981)'
                                : 'var(--text-muted)',

                            borderBottom:
                              centerTab ===
                              id
                                ? '2px solid var(--accent-green,#10B981)'
                                : '2px solid transparent',
                          }}
                        >
                          {label}
                        </button>
                      )
                    )}

                  </div>

                  {centerTab ===
                    'graph' && (
                    <NetworkGraph
                      height={380}
                    />
                  )}

                  {centerTab ===
                    'map' && (
                    <ThreatMap
                      onCountryClick={
                        setSelectedCountry
                      }

                      selectedCountry={
                        selectedCountry
                      }
                    />
                  )}
                </>
              )}

              {view3D && (
                <GlobeStats
                  incidents={
                    incidents
                  }
                />
              )}

            </div>

          </div>


          <div
            style={{
              borderTop:
                '1px solid var(--border-subtle)',
            }}
          >
            <ASNHealthGrid />
          </div>

          <OperationalTimeline />

        </div>


        {/* RIGHT */}

        <div
          style={{
            overflowY: 'auto',

            padding: 16,

            background:
              'rgba(6,10,15,0.9)',
          }}
        >

          <PanelErrorBoundary
            incidentId={
              selectedIncidentId
            }
          >

            {selectedIncident ? (
              <DetailPanel
                incident={
                  selectedIncident
                }
              />
            ) : (
              <>
                <EmptyState
                  apnicReady={
                    apnicReady
                  }
                />

                <div
                  style={{
                    marginTop: 12,

                    border:
                      '1px solid var(--border-subtle)',

                    borderRadius: 6,

                    overflow: 'hidden',

                    height: 420,
                  }}
                >

                  <div
                    style={{
                      padding:
                        '8px 12px',

                      borderBottom:
                        '1px solid var(--border-subtle)',

                      fontFamily:
                        'var(--font-display)',

                      fontSize: 11,

                      fontWeight: 700,
                    }}
                  >
                    ON-DEVICE NPU MONITOR
                  </div>

                  <SnapShieldPanel />

                </div>
              </>
            )}

          </PanelErrorBoundary>

        </div>

      </main>


      <Footer />

      <AINotification />


      {showBreach && (
        <Suspense
          fallback={
            <PanelFallback />
          }
        >
          <BreachSimulator
            onClose={() =>
              setShowBreach(
                false
              )
            }

            onIncidentGenerated={
              onBreachIncident
            }
          />
        </Suspense>
      )}


      {historyCountry && (
        <Suspense
          fallback={
            <PanelFallback />
          }
        >
          <CountryHistoryPage
            countryCode={
              historyCountry
            }

            onBack={() =>
              setHistoryCountry(
                null
              )
            }
          />
        </Suspense>
      )}

    </div>
  )
}


// -----------------------------------------------------------------------------
// Globe statistics
// -----------------------------------------------------------------------------

function GlobeStats({
  incidents,
}) {
  const attackMap =
    new Map()

  let unresolved = 0

  let totalActive = 0

  for (
    const incident of incidents
  ) {
    if (
      incident.status ===
      'MITIGATED'
    ) {
      continue
    }

    totalActive++

    const country =
      incident.attacker?.country

    if (
      !country ||
      country === '??'
    ) {
      unresolved++
      continue
    }

    const existing =
      attackMap.get(
        country
      )

    if (
      !existing ||
      SEVERITY_ORDER.indexOf(
        incident.severity
      ) <
        SEVERITY_ORDER.indexOf(
          existing.severity
        )
    ) {
      attackMap.set(
        country,
        incident
      )
    }
  }

  const attacks =
    Array.from(
      attackMap.entries()
    )

  const avgConfidence =
    attacks.length
      ? Math.round(
          attacks.reduce(
            (
              total,
              [, incident]
            ) =>
              total +
              (
                incident.confidence ??
                0
              ),
            0
          ) /
            attacks.length
        )
      : 0

  return (
    <>
      <div
        style={{
          display: 'flex',

          borderTop:
            '1px solid var(--border-subtle)',
        }}
      >

        {[
          [
            'Attack Origins',
            attacks.length,
          ],

          [
            'Active Attacks',
            totalActive,
          ],

          [
            'Avg Confidence',
            attacks.length
              ? `${avgConfidence}%`
              : '—',
          ],
        ].map(
          ([label, value]) => (
            <div
              key={label}
              style={{
                flex: 1,

                padding:
                  '8px 0',

                textAlign:
                  'center',

                borderRight:
                  '1px solid var(--border-subtle)',
              }}
            >

              <div
                style={{
                  fontFamily:
                    'var(--font-display)',

                  fontSize: 18,

                  fontWeight: 800,

                  color:
                    'var(--text-primary)',
                }}
              >
                {value}
              </div>

              <div
                style={{
                  fontFamily:
                    'var(--font-mono)',

                  fontSize: 8,

                  color:
                    'var(--text-muted)',

                  letterSpacing: 1,
                }}
              >
                {label}
              </div>

            </div>
          )
        )}

      </div>


      {unresolved > 0 && (
        <div
          style={{
            padding:
              '5px 16px',

            borderTop:
              '1px solid var(--border-subtle)',

            display: 'flex',

            alignItems:
              'center',

            gap: 6,
          }}
        >

          <div
            style={{
              width: 5,
              height: 5,
              borderRadius: '50%',
              background: '#ffd60a',
              animation:
                'termBlink 1.2s ease infinite',
            }}
          />

          <span
            style={{
              fontFamily:
                'var(--font-mono)',

              fontSize: 8,

              color:
                'var(--text-muted)',
            }}
          >
            Resolving origin for{' '}
            {unresolved}{' '}
            incident
            {unresolved > 1
              ? 's'
              : ''}{' '}
            via RIPE STAT...
          </span>

        </div>
      )}

    </>
  )
}


// -----------------------------------------------------------------------------
// Empty state
// -----------------------------------------------------------------------------

function EmptyState({
  apnicReady,
}) {
  const appMode =
    useSHYENStore(
      s => s.appMode
    )

  return (
    <div
      style={{
        display: 'flex',

        flexDirection:
          'column',

        alignItems:
          'center',

        justifyContent:
          'center',

        height: '100%',

        gap: 16,
      }}
    >

      <div
        style={{
          width: 48,
          height: 48,

          border:
            '1px solid rgba(0,255,136,0.15)',

          borderRadius:
            '50%',

          display: 'flex',

          alignItems:
            'center',

          justifyContent:
            'center',
        }}
      >

        <div
          style={{
            width: 8,
            height: 8,

            borderRadius:
              '50%',

            background:
              apnicReady
                ? 'var(--accent-green)'
                : '#ffd60a',

            animation:
              'pulse 2s ease infinite',

            boxShadow:
              `0 0 8px ${
                apnicReady
                  ? 'var(--accent-green)'
                  : '#ffd60a'
              }`,
          }}
        />

      </div>


      <div
        style={{
          textAlign:
            'center',
        }}
      >

        <div
          style={{
            fontFamily:
              'var(--font-mono)',

            fontSize: 10,

            color:
              'var(--text-muted)',

            letterSpacing: 2,

            marginBottom: 6,
          }}
        >
          {apnicReady
            ? 'MONITORING LIVE BGP + NPU THREAT FEED'
            : 'LOADING PREFIX DATABASE...'}
        </div>

        <div
          style={{
            fontFamily:
              'var(--font-mono)',

            fontSize: 8,

            color: '#222',

            letterSpacing: 1,

            lineHeight: 1.8,
          }}
        >
          {!apnicReady
            ? 'Fetching APNIC delegation file...'
            : appMode === 'demo'
              ? (
                <>
                  Select an incident · Press{' '}
                  <span
                    style={{
                      color:
                        '#ff2d55',
                    }}
                  >
                    B
                  </span>{' '}
                  to simulate
                </>
              )
              : 'Select an incident'}
        </div>

      </div>


      <style>
        {`
          @keyframes pulse {
            0%,100% {
              opacity: 1;
            }

            50% {
              opacity: 0.3;
            }
          }
        `}
      </style>

    </div>
  )
}
