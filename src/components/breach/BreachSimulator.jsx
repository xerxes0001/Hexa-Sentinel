import { useState, useEffect, useRef } from 'react'
import { INDIAN_ASNS } from '../../data/indianASNs.js'
import { FOREIGN_ASNS } from '../../data/foreignASNs.js'
import { SEVERITY_COLORS as SEV_COLOR } from '../../utils/severity.js'

const PRODUCT_NAME = 'HEXASENTINEL'
const PRODUCT_SUBTITLE = 'ON-DEVICE BGP THREAT INTELLIGENCE'

const BREACH_TYPES = [
  {
    id: 'ORIGIN_HIJACK',
    label: 'Origin Hijack',
    icon: '⬡',
    severity: 'CRITICAL',
    desc: 'Foreign ASN claims origin of an Indian network prefix',
  },
  {
    id: 'SUBPREFIX_HIJACK',
    label: 'Sub-prefix Hijack',
    icon: '◈',
    severity: 'HIGH',
    desc: 'More-specific route injected to capture traffic',
  },
  {
    id: 'ROUTE_LEAK',
    label: 'Route Leak',
    icon: '⟳',
    severity: 'HIGH',
    desc: 'Indian route propagates through an unexpected ASN path',
  },
  {
    id: 'PATH_MANIPULATION',
    label: 'Path Manipulation',
    icon: '↯',
    severity: 'MEDIUM',
    desc: 'Unexpected ASN insertion or path alteration detected',
  },
]

const SECTOR_COLORS = {
  Financial: '#ff2d55',
  Government: '#ffd60a',
  Defense: '#ff6b00',
  Telecom: '#00bfff',
  ISP: '#00ff88',
  IXP: '#bf5af2',
}

/*
 * Deterministic incident ID.
 *
 * The previous version used Math.random(), which made the same
 * simulation produce different identifiers on every run.
 */
function createIncidentId(breach, victim, attacker, prefix) {
  const input = `${breach.id}:${victim.asn}:${attacker.asn}:${prefix}`

  let hash = 0

  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0
  }

  return String(Math.abs(hash) % 9000 + 1000)
}

/*
 * Deterministic prefix selection.
 *
 * This avoids selecting a different prefix every time the demo
 * is launched.
 */
function selectPrefix(victim) {
  if (!victim?.prefixes?.length) return '0.0.0.0/0'

  return victim.prefixes[0]
}

function calculateAffectedIPs(prefix) {
  const bits = parseInt(prefix?.split('/')[1] ?? '24', 10)

  if (!Number.isFinite(bits) || bits < 0 || bits > 32) {
    return 0
  }

  return Math.pow(2, 32 - bits)
}

function calculateConfidence(breach) {
  switch (breach.severity) {
    case 'CRITICAL':
      return 95

    case 'HIGH':
      return 87

    case 'MEDIUM':
      return 78

    default:
      return 70
  }
}

function buildScript(breach, victim, attacker, prefix) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19)

  const affectedIPs = calculateAffectedIPs(prefix)
  const confidence = calculateConfidence(breach)

  const incidentId = createIncidentId(
    breach,
    victim,
    attacker,
    prefix
  )

  const path = [
    attacker.asn,
    'AS174',
    'AS3356',
    victim.asn,
  ].join(' ')

  return [
    { t: '', c: '', d: 0 },

    {
      t: `${PRODUCT_NAME} — ${PRODUCT_SUBTITLE}`,
      c: '#00ff88',
      bold: true,
      d: 0,
    },

    {
      t: 'On-device AI · Llama 3.2 3B · Qualcomm Hexagon NPU',
      c: '#4d8a63',
      d: 60,
    },

    {
      t: '',
      d: 80,
    },

    {
      t: '────────────────────────────────────────────────────────────',
      c: '#2f3a48',
      d: 60,
    },

    {
      t: `[${ts} UTC]  ANOMALY STREAM ACTIVE — monitoring ${INDIAN_ASNS.length} Indian ASNs`,
      c: '#7c8697',
      d: 80,
    },

    {
      t: `[${ts} UTC]  Vantage feed: RIPE RIS / RouteViews`,
      c: '#7c8697',
      d: 100,
    },

    {
      t: '',
      d: 200,
    },

    {
      t: `[${ts} UTC]  BGP UPDATE RECEIVED`,
      c: '#8b96a4',
      d: 80,
    },

    {
      t: `[${ts} UTC]  Origin AS: ${attacker.asn} (${attacker.name})`,
      c: '#8b96a4',
      d: 80,
    },

    {
      t: `[${ts} UTC]  Announced Prefix: ${prefix}`,
      c: '#8b96a4',
      d: 80,
    },

    {
      t: `[${ts} UTC]  AS_PATH: ${path}`,
      c: '#8b96a4',
      d: 100,
    },

    {
      t: '',
      d: 180,
    },

    {
      t: `[${ts} UTC]  EXPECTED ORIGIN -> ${victim.asn} (${victim.name})`,
      c: '#8b96a4',
      d: 100,
    },

    {
      t: `[${ts} UTC]  OBSERVED ORIGIN -> ${attacker.asn} [${attacker.country}]`,
      c: '#ff6b00',
      d: 100,
    },

    {
      t: `[${ts} UTC]  ORIGIN MISMATCH DETECTED`,
      c: '#ff2d55',
      bold: true,
      d: 120,
    },

    {
      t: '',
      d: 160,
    },

    {
      t: `[${ts} UTC]  VALIDATION: checking available BGP vantage points...`,
      c: '#8b96a4',
      d: 100,
    },

    {
      t: `[${ts} UTC]  RIPE RIS ......................... OBSERVED`,
      c: '#00ff88',
      d: 80,
    },

    {
      t: `[${ts} UTC]  RouteViews ....................... OBSERVED`,
      c: '#00ff88',
      d: 80,
    },

    {
      t: `[${ts} UTC]  Cross-vantage validation ........ COMPLETE`,
      c: '#00ff88',
      d: 100,
    },

    {
      t: '',
      d: 140,
    },

    {
      t: `[${ts} UTC]  CONFIDENCE: ${confidence}%`,
      c: '#ffd60a',
      d: 100,
    },

    {
      t: `[${ts} UTC]  AFFECTED IPs: ~${affectedIPs.toLocaleString()}`,
      c: '#ffd60a',
      d: 80,
    },

    {
      t: `[${ts} UTC]  SECTOR: ${victim.sector}`,
      c: '#ffd60a',
      d: 80,
    },

    {
      t: '',
      d: 200,
    },

    {
      t: '────────────────────────────────────────────────────────────',
      c: '#ff2d55',
      d: 60,
    },

    {
      t: '',
      d: 40,
    },

    {
      t: '  HEXASENTINEL ALERT',
      c: '#ff2d55',
      bold: true,
      d: 40,
    },

    {
      t: `  ${breach.severity} INCIDENT DETECTED`,
      c: '#ff2d55',
      bold: true,
      d: 40,
    },

    {
      t: `  ${breach.label.toUpperCase()}`,
      c: '#ff2d55',
      bold: true,
      d: 40,
    },

    {
      t: '',
      d: 40,
    },

    {
      t: '────────────────────────────────────────────────────────────',
      c: '#ff2d55',
      d: 60,
    },

    {
      t: '',
      d: 80,
    },

    {
      t: `  TARGET      ${victim.name} (${victim.asn})`,
      c: '#e8e8e8',
      bold: true,
      d: 60,
    },

    {
      t: `  SECTOR      ${victim.sector}`,
      c: '#888',
      d: 50,
    },

    {
      t: `  PREFIX      ${prefix}`,
      c: '#888',
      d: 50,
    },

    {
      t: `  OBSERVED    ${attacker.asn} — ${attacker.name} [${attacker.country}]`,
      c: '#ff6b00',
      d: 50,
    },

    {
      t: `  IPs AFFECTED ~${affectedIPs.toLocaleString()} addresses`,
      c: '#888',
      d: 50,
    },

    {
      t: `  CONFIDENCE  ${confidence}%`,
      c: '#888',
      d: 50,
    },

    {
      t: '',
      d: 100,
    },

    {
      t: `  ${breach.desc}`,
      c: '#9aa5b1',
      d: 60,
    },

    {
      t: '',
      d: 120,
    },

    {
      t: '────────────────────────────────────────────────────────────',
      c: '#2f3a48',
      d: 60,
    },

    {
      t: '',
      d: 80,
    },

    {
      t: '[HEXASENTINEL RESPONSE PIPELINE]',
      c: '#00bfff',
      bold: true,
      d: 100,
    },

    {
      t: '',
      d: 60,
    },

    {
      t: '  -> Building evidence record...',
      c: '#7c8697',
      d: 220,
    },

    {
      t: '  OK BGP evidence captured',
      c: '#00ff88',
      d: 280,
    },

    {
      t: '',
      d: 60,
    },

    {
      t: '  -> Recording RPKI validation state...',
      c: '#7c8697',
      d: 220,
    },

    {
      t: '  OK RPKI validation queued',
      c: '#00ff88',
      d: 280,
    },

    {
      t: '',
      d: 60,
    },

    {
      t: '  -> Building forensic evidence bundle...',
      c: '#7c8697',
      d: 220,
    },

    {
      t: '  OK Forensic evidence package prepared',
      c: '#00ff88',
      d: 280,
    },

    {
      t: '',
      d: 60,
    },

    {
      t: '  -> Updating HexaSentinel incident state...',
      c: '#7c8697',
      d: 220,
    },

    {
      t: '  OK Incident state recorded locally',
      c: '#00ff88',
      d: 280,
    },

    {
      t: '',
      d: 120,
    },

    {
      t: '────────────────────────────────────────────────────────────',
      c: '#2f3a48',
      d: 60,
    },

    {
      t: `[${ts} UTC]  INCIDENT #${incidentId} LOGGED`,
      c: '#ffd60a',
      d: 80,
    },

    {
      t: `[${ts} UTC]  STATUS: UNDER INVESTIGATION`,
      c: '#ffd60a',
      d: 80,
    },

    {
      t: `[${ts} UTC]  HexaSentinel monitoring ${INDIAN_ASNS.length} Indian ASNs`,
      c: '#7c8697',
      d: 80,
    },

    {
      t: '',
      d: 200,
    },

    {
      t: 'Press any key or click DISMISS to return to dashboard',
      c: '#00ff88',
      blink: true,
      d: 0,
    },
  ]
}

function TerminalOverlay({
  breach,
  victim,
  attacker,
  prefix,
  onDismiss,
}) {
  const [lines, setLines] = useState([])
  const [done, setDone] = useState(false)

  const scrollRef = useRef(null)

  const script = useRef(
    buildScript(
      breach,
      victim,
      attacker,
      prefix
    )
  )

  useEffect(() => {
    let i = 0
    let timeout

    function next() {
      if (i >= script.current.length) {
        setDone(true)
        return
      }

      const line = script.current[i++]

      setLines(prev => [
        ...prev,
        line,
      ])

      timeout = setTimeout(
        next,
        line.d ?? 60
      )
    }

    timeout = setTimeout(
      next,
      200
    )

    return () => clearTimeout(timeout)
  }, [])

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop =
        scrollRef.current.scrollHeight
    }
  }, [lines])

  useEffect(() => {
    if (!done) return

    const fn = () => {
      onDismiss()
    }

    window.addEventListener(
      'keydown',
      fn
    )

    return () => {
      window.removeEventListener(
        'keydown',
        fn
      )
    }
  }, [done, onDismiss])

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 200,
        background: 'rgba(0,0,0,0.98)',
        display: 'flex',
        flexDirection: 'column',
        fontFamily:
          "'JetBrains Mono','Courier New',monospace",
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 1,
          background:
            'repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.07) 2px,rgba(0,0,0,0.07) 4px)',
        }}
      />

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 20px',
          borderBottom: '1px solid #111',
          background: '#060606',
          zIndex: 2,
          flexShrink: 0,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <div
            style={{
              width: 11,
              height: 11,
              borderRadius: '50%',
              background: '#ff2d55',
              boxShadow:
                '0 0 5px #ff2d55',
            }}
          />

          <div
            style={{
              width: 11,
              height: 11,
              borderRadius: '50%',
              background: '#ffd60a',
            }}
          />

          <div
            style={{
              width: 11,
              height: 11,
              borderRadius: '50%',
              background: '#30d158',
            }}
          />

          <span
            style={{
              fontSize: 10,
              color: '#6b7686',
              marginLeft: 12,
              letterSpacing: '0.1em',
            }}
          >
            hexasentinel@hexagon-npu — incident-terminal
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background:
                'rgba(255,45,85,0.08)',
              border:
                '1px solid rgba(255,45,85,0.2)',
              borderRadius: 3,
              padding: '3px 10px',
            }}
          >
            <div
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#ff2d55',
                animation:
                  'termBlink 0.8s ease infinite',
              }}
            />

            <span
              style={{
                fontSize: 9,
                color: '#ff2d55',
                letterSpacing: '0.12em',
              }}
            >
              ANOMALY DETECTED
            </span>
          </div>

          {done && (
            <button
              onClick={onDismiss}
              style={{
                fontFamily: 'inherit',
                fontSize: 9,
                color: '#8b96a4',
                background: 'transparent',
                border:
                  '1px solid #3a4452',
                borderRadius: 3,
                padding: '4px 12px',
                cursor: 'pointer',
                letterSpacing: '0.1em',
              }}
            >
              DISMISS ×
            </button>
          )}
        </div>
      </div>

      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '20px 28px 40px',
          position: 'relative',
          zIndex: 2,
        }}
      >
        {lines.map((line, i) => (
          <div
            key={i}
            style={{
              lineHeight: 1.75,
              minHeight: '1.75em',
              whiteSpace: 'pre',
              fontSize:
                line.bold ? 11.5 : 10.5,
              color:
                line.c || '#8b96a4',
              fontWeight:
                line.bold ? 700 : 400,
              textShadow:
                line.c === '#ff2d55'
                  ? '0 0 8px rgba(255,45,85,0.35)'
                  : line.c === '#00ff88'
                    ? '0 0 5px rgba(0,255,136,0.25)'
                    : 'none',
              animation:
                line.blink
                  ? 'termBlink 1.2s ease infinite'
                  : 'none',
            }}
          >
            {line.t}
          </div>
        ))}

        {!done && (
          <div
            style={{
              display: 'inline-block',
              width: 7,
              height: 13,
              background: '#00ff88',
              animation:
                'termBlink 1s ease infinite',
              verticalAlign: 'middle',
              marginLeft: 2,
            }}
          />
        )}
      </div>

      <style>
        {`
          @keyframes termBlink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
          }

          ::-webkit-scrollbar {
            width: 3px;
          }

          ::-webkit-scrollbar-thumb {
            background: #111;
          }
        `}
      </style>
    </div>
  )
}

function StepLabel({
  n,
  label,
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        marginBottom: 10,
      }}
    >
      <span
        style={{
          fontSize: 8,
          color: '#ff2d55',
          fontWeight: 700,
          letterSpacing: '0.08em',
        }}
      >
        {n}
      </span>

      <div
        style={{
          flex: 1,
          height: 1,
          background:
            'rgba(255,255,255,0.04)',
        }}
      />

      <span
        style={{
          fontSize: 8,
          color: '#a3aebb',
          letterSpacing: '0.14em',
        }}
      >
        {label}
      </span>

      <div
        style={{
          flex: 1,
          height: 1,
          background:
            'rgba(255,255,255,0.04)',
        }}
      />
    </div>
  )
}

export default function BreachSimulator({
  onClose,
  onIncidentGenerated,
}) {
  const [breach, setBreach] = useState(null)
  const [victim, setVictim] = useState(null)
  const [attacker, setAttacker] = useState(null)
  const [terminal, setTerminal] = useState(null)

  const ready =
    breach &&
    victim &&
    attacker

  function launch() {
    if (!ready) return

    const v =
      INDIAN_ASNS.find(
        a => a.asn === victim
      )

    const a =
      FOREIGN_ASNS.find(
        a => a.asn === attacker
      )

    const b =
      BREACH_TYPES.find(
        item => item.id === breach
      )

    if (!v || !a || !b) return

    const prefix =
      selectPrefix(v)

    setTerminal({
      breach: b,
      victim: v,
      attacker: a,
      prefix,
    })
  }

  /*
   * Deterministic quick demo:
   *
   * Indian target:
   * AS55655
   *
   * Foreign origin:
   * AS4134
   *
   * This is explicitly marked as simulated data when
   * sent back to the application.
   */
  function quickDemo() {
    const v =
      INDIAN_ASNS.find(
        a => a.asn === 'AS55655'
      ) ?? INDIAN_ASNS[0]

    const a =
      FOREIGN_ASNS.find(
        a => a.asn === 'AS4134'
      ) ?? FOREIGN_ASNS[0]

    const b =
      BREACH_TYPES.find(
        item =>
          item.id ===
          'ORIGIN_HIJACK'
      )

    if (!v || !a || !b) return

    const prefix =
      selectPrefix(v)

    setTerminal({
      breach: b,
      victim: v,
      attacker: a,
      prefix,
    })
  }

  function handleDismiss() {
    if (!terminal) {
      onClose?.()
      return
    }

    const affectedIPs =
      calculateAffectedIPs(
        terminal.prefix
      )

    const confidence =
      calculateConfidence(
        terminal.breach
      )

    const incidentId =
      createIncidentId(
        terminal.breach,
        terminal.victim,
        terminal.attacker,
        terminal.prefix
      )

    const incident = {
      id: incidentId,

      type:
        terminal.breach.id,

      severity:
        terminal.breach.severity,

      victim:
        terminal.victim,

      attacker:
        terminal.attacker,

      prefix:
        terminal.prefix,

      timestamp:
        new Date(),

      affectedIPs,

      confidence,

      isSimulated: true,

      isRealData: false,

      source:
        'HexaSentinel Breach Simulator',

      confirmedPoints: [
        'RIPE RIS',
        'RouteViews',
      ],

      /*
       * Explicitly identifies this as a simulation.
       * This prevents simulated events from being mistaken
       * for live BGP observations downstream.
       */
      simulation: {
        enabled: true,
        scenario:
          terminal.breach.id,
        generatedBy:
          'HexaSentinel Breach Simulator',
      },
    }

    onIncidentGenerated?.(
      incident
    )

    setTerminal(null)
    onClose?.()
  }

  if (terminal) {
    return (
      <TerminalOverlay
        breach={terminal.breach}
        victim={terminal.victim}
        attacker={terminal.attacker}
        prefix={terminal.prefix}
        onDismiss={handleDismiss}
      />
    )
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        background:
          'rgba(0,0,0,0.92)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily:
          'var(--font-mono)',
      }}
      onClick={e => {
        if (
          e.target ===
          e.currentTarget
        ) {
          onClose?.()
        }
      }}
    >
      <div
        style={{
          width: 660,
          maxHeight: '90vh',
          overflowY: 'auto',
          background: '#060b10',
          border:
            '1px solid rgba(255,45,85,0.18)',
          borderRadius: 8,
          padding:
            '28px 28px 24px',
          boxShadow:
            '0 0 60px rgba(255,45,85,0.06)',
        }}
      >
        <div
          style={{
            marginBottom: 28,
            display: 'flex',
            justifyContent:
              'space-between',
            alignItems:
              'flex-start',
          }}
        >
          <div>
            <div
              style={{
                fontSize: 9,
                color: '#ff2d55',
                letterSpacing:
                  '0.18em',
                marginBottom: 6,
              }}
            >
              {PRODUCT_NAME} NPU MONITOR
            </div>

            <div
              style={{
                fontFamily:
                  'var(--font-display)',
                fontSize: 22,
                fontWeight: 800,
                color: '#fff',
                lineHeight: 1,
              }}
            >
              Breach Simulator
            </div>

            <div
              style={{
                fontSize: 9,
                color: '#8b96a4',
                marginTop: 6,
              }}
            >
              Configure a simulated BGP
              anomaly for demonstration
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background:
                'rgba(255,45,85,0.08)',
              border:
                '1px solid rgba(255,45,85,0.5)',
              color: '#ff2d55',
              borderRadius: 3,
              padding: '5px 12px',
              cursor: 'pointer',
              fontSize: 11,
              fontFamily:
                'var(--font-mono)',
              boxShadow:
                '0 0 8px rgba(255,45,85,0.35)',
              letterSpacing: 1,
            }}
          >
            ✕ CLOSE
          </button>
        </div>

        <button
          onClick={quickDemo}
          style={{
            width: '100%',
            marginBottom: 20,
            fontFamily:
              'var(--font-mono)',
            fontSize: 11,
            fontWeight: 700,
            letterSpacing:
              '0.12em',
            color: '#fff',
            background:
              'linear-gradient(135deg, #ff2d55, #ff6b00)',
            border: 'none',
            borderRadius: 5,
            padding: '12px 0',
            cursor: 'pointer',
            boxShadow:
              '0 0 24px rgba(255,45,85,0.35)',
            display: 'flex',
            alignItems: 'center',
            justifyContent:
              'center',
            gap: 8,
          }}
        >
          ⚡ QUICK DEMO — CRITICAL ORIGIN HIJACK
        </button>

        <div
          style={{
            textAlign: 'center',
            fontSize: 8,
            color: '#8b96a4',
            marginBottom: 20,
            marginTop: -12,
            letterSpacing:
              '0.05em',
          }}
        >
          Simulated scenario — clearly
          separated from live BGP data
        </div>

        <StepLabel
          n="01"
          label="SELECT BREACH TYPE"
        />

        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              '1fr 1fr',
            gap: 6,
            marginBottom: 24,
          }}
        >
          {BREACH_TYPES.map(b => {
            const selected =
              breach === b.id

            const color =
              SEV_COLOR[
                b.severity
              ]

            return (
              <div
                key={b.id}
                onClick={() =>
                  setBreach(b.id)
                }
                style={{
                  border:
                    `1px solid ${
                      selected
                        ? color + '80'
                        : 'rgba(255,255,255,0.06)'
                    }`,
                  background:
                    selected
                      ? color + '0d'
                      : 'rgba(255,255,255,0.01)',
                  borderRadius: 5,
                  padding:
                    '10px 12px',
                  cursor: 'pointer',
                  transition:
                    'all 0.15s',
                }}
              >
                <div
                  style={{
                    display:
                      'flex',
                    alignItems:
                      'center',
                    gap: 7,
                    marginBottom: 5,
                  }}
                >
                  <span
                    style={{
                      fontSize: 14,
                      color:
                        selected
                          ? color
                          : '#5c6773',
                    }}
                  >
                    {b.icon}
                  </span>

                  <span
                    style={{
                      fontSize: 9,
                      color:
                        selected
                          ? color
                          : '#9aa5b1',
                      letterSpacing:
                        '0.08em',
                      fontWeight: 700,
                    }}
                  >
                    {b.label.toUpperCase()}
                  </span>

                  <span
                    style={{
                      marginLeft:
                        'auto',
                      fontSize: 8,
                      color,
                      border:
                        `1px solid ${color}44`,
                      borderRadius: 2,
                      padding:
                        '1px 4px',
                    }}
                  >
                    {b.severity}
                  </span>
                </div>

                <div
                  style={{
                    fontSize: 9,
                    color:
                      selected
                        ? '#c3ccd6'
                        : '#8b96a4',
                    lineHeight: 1.5,
                  }}
                >
                  {b.desc}
                </div>
              </div>
            )
          })}
        </div>

        <StepLabel
          n="02"
          label="SELECT TARGET ASN"
        />

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 5,
            marginBottom: 24,
          }}
        >
          {INDIAN_ASNS.map(asn => {
            const selected =
              victim === asn.asn

            const color =
              SECTOR_COLORS[
                asn.sector
              ] ?? '#888'

            return (
              <div
                key={asn.asn}
                onClick={() =>
                  setVictim(
                    asn.asn
                  )
                }
                style={{
                  border:
                    `1px solid ${
                      selected
                        ? color + '80'
                        : 'rgba(255,255,255,0.05)'
                    }`,
                  background:
                    selected
                      ? color + '0d'
                      : 'rgba(255,255,255,0.01)',
                  borderRadius: 4,
                  padding:
                    '6px 10px',
                  cursor: 'pointer',
                  transition:
                    'all 0.15s',
                }}
              >
                <div
                  style={{
                    fontSize: 8,
                    color:
                      selected
                        ? color
                        : '#7c8697',
                  }}
                >
                  {asn.asn}
                </div>

                <div
                  style={{
                    fontSize: 10,
                    color:
                      selected
                        ? '#ddd'
                        : '#a3aebb',
                    fontWeight:
                      selected
                        ? 600
                        : 400,
                  }}
                >
                  {asn.name}
                </div>

                <div
                  style={{
                    fontSize: 8,
                    color:
                      selected
                        ? color
                        : '#6b7686',
                    marginTop: 1,
                  }}
                >
                  {asn.sector}
                </div>
              </div>
            )
          })}
        </div>

        <StepLabel
          n="03"
          label="SELECT OBSERVED ORIGIN"
        />

        <div
          style={{
            display: 'flex',
            gap: 6,
            marginBottom: 28,
            flexWrap: 'wrap',
          }}
        >
          {FOREIGN_ASNS.map(asn => {
            const selected =
              attacker === asn.asn

            const color =
              asn.country === 'CN' ||
              asn.country === 'PK'
                ? '#ff6b00'
                : '#9aa5b1'

            const flag =
              {
                CN: 'CN',
                PK: 'PK',
                EG: 'EG',
                DE: 'DE',
                IT: 'IT',
                US: 'US',
                AU: 'AU',
                JP: 'JP',
              }[asn.country] ??
              '--'

            return (
              <div
                key={asn.asn}
                onClick={() =>
                  setAttacker(
                    asn.asn
                  )
                }
                style={{
                  border:
                    `1px solid ${
                      selected
                        ? color + '80'
                        : 'rgba(255,255,255,0.05)'
                    }`,
                  background:
                    selected
                      ? color + '0d'
                      : 'rgba(255,255,255,0.01)',
                  borderRadius: 4,
                  padding:
                    '8px 12px',
                  cursor: 'pointer',
                  transition:
                    'all 0.15s',
                  flex: 1,
                  minWidth: 90,
                  textAlign: 'center',
                }}
              >
                <div
                  style={{
                    fontSize: 13,
                    color:
                      selected
                        ? color
                        : '#a3aebb',
                    fontWeight: 700,
                    marginBottom: 4,
                  }}
                >
                  [{flag}]
                </div>

                <div
                  style={{
                    fontSize: 8,
                    color:
                      selected
                        ? color
                        : '#7c8697',
                  }}
                >
                  {asn.asn}
                </div>

                <div
                  style={{
                    fontSize: 9,
                    color:
                      selected
                        ? '#ddd'
                        : '#a3aebb',
                    fontWeight:
                      selected
                        ? 600
                        : 400,
                  }}
                >
                  {asn.name}
                </div>
              </div>
            )
          })}
        </div>

        <button
          onClick={launch}
          disabled={!ready}
          style={{
            width: '100%',
            fontFamily:
              'var(--font-mono)',
            fontSize: 12,
            fontWeight: 700,
            letterSpacing:
              '0.15em',
            color: ready
              ? '#000'
              : '#7c8697',
            background: ready
              ? '#ff2d55'
              : 'rgba(255,255,255,0.02)',
            border:
              `1px solid ${
                ready
                  ? '#ff2d55'
                  : 'rgba(255,255,255,0.04)'
              }`,
            borderRadius: 5,
            padding: '13px 0',
            cursor: ready
              ? 'pointer'
              : 'not-allowed',
            transition:
              'all 0.2s',
            boxShadow: ready
              ? '0 0 20px rgba(255,45,85,0.25)'
              : 'none',
          }}
        >
          {ready
            ? 'SIMULATE BGP INCIDENT'
            : '— SELECT ALL THREE TO CONTINUE —'}
        </button>

        {ready && (
          <div
            style={{
              marginTop: 10,
              textAlign: 'center',
              fontSize: 9,
              color: '#7c8697',
            }}
          >
            Simulation only — no network
            changes are performed
          </div>
        )}
      </div>
    </div>
  )
}
