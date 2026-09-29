import { useState } from 'react'

const THREATS = [
  {
    id: 'SUSPICIOUS_PROCESS',
    label: 'Suspicious Process',
    severity: 'HIGH',
  },
  {
    id: 'MALICIOUS_FILE',
    label: 'Malicious File',
    severity: 'CRITICAL',
  },
  {
    id: 'PERSISTENCE',
    label: 'Persistence Attempt',
    severity: 'HIGH',
  },
  {
    id: 'NETWORK_BEHAVIOR',
    label: 'Suspicious Network Activity',
    severity: 'MEDIUM',
  },
]

const COLORS = {
  LOW: '#30d158',
  MEDIUM: '#ffd60a',
  HIGH: '#ff6b00',
  CRITICAL: '#ff2d55',
}

export default function ThreatSimulator({
  onClose,
  onIncidentGenerated,
}) {
  const [selected, setSelected] = useState(null)
  const [running, setRunning] = useState(false)

  function simulate() {
    if (!selected) return

    setRunning(true)

    const threat = THREATS.find(
      t => t.id === selected
    )

    setTimeout(() => {
      const incident = {
        id: `SIM-${Date.now()}`,

        type: threat.id,

        severity: threat.severity,

        title: threat.label,

        timestamp: new Date(),

        isSimulated: true,

        isRealData: false,

        blocked: false,

        quarantined: false,

        processes:
          threat.id === 'SUSPICIOUS_PROCESS'
            ? [
                {
                  pid: 4821,
                  name: 'suspicious.exe',
                  path: 'C:\\Users\\User\\Downloads\\suspicious.exe',
                  suspicious: true,
                  severity: 'HIGH',
                },
              ]
            : [],

        files:
          threat.id === 'MALICIOUS_FILE'
            ? [
                {
                  path: 'C:\\Users\\User\\Downloads\\payload.exe',
                  severity: 'CRITICAL',
                },
                {
                  path: 'C:\\Users\\User\\AppData\\Local\\Temp\\stage.dat',
                  severity: 'HIGH',
                },
              ]
            : [],

        networkConnections:
          threat.id === 'NETWORK_BEHAVIOR'
            ? [
                {
                  remote: 'suspicious.example',
                  protocol: 'HTTPS',
                  blocked: false,
                },
              ]
            : [],

        persistence:
          threat.id === 'PERSISTENCE'
            ? [
                {
                  type: 'STARTUP',
                  location: 'User startup configuration',
                  severity: 'HIGH',
                },
              ]
            : [],

        deterministicSummary:
          `${threat.label} simulation generated for local endpoint testing.`,

        demoAnalysisText:
          `HEXSENTINEL SIMULATION\n\n` +
          `THREAT: ${threat.label}\n` +
          `SEVERITY: ${threat.severity}\n\n` +
          `This is simulated telemetry. No real system changes were performed.`,
      }

      setRunning(false)
      onIncidentGenerated?.(incident)
      onClose?.()
    }, 700)
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100,
        background: 'rgba(0,0,0,0.92)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-mono)',
      }}
      onClick={e => {
        if (e.target === e.currentTarget) {
          onClose?.()
        }
      }}
    >
      <div
        style={{
          width: 620,
          maxWidth: 'calc(100vw - 30px)',
          background: '#060b10',
          border: '1px solid rgba(0,191,255,0.25)',
          borderRadius: 7,
          padding: 25,
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            marginBottom: 25,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 8,
                color: '#00bfff',
                letterSpacing: '0.16em',
              }}
            >
              HEXASENTINEL ENDPOINT MONITOR
            </div>

            <div
              style={{
                marginTop: 6,
                fontFamily: 'var(--font-display)',
                fontSize: 21,
                fontWeight: 800,
                color: '#fff',
              }}
            >
              Threat Simulator
            </div>

            <div
              style={{
                marginTop: 5,
                fontSize: 8,
                color: 'var(--text-muted)',
              }}
            >
              Generate synthetic endpoint telemetry
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.15)',
              color: '#8b96a4',
              borderRadius: 3,
              padding: '5px 10px',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
            }}
          >
            ✕
          </button>
        </div>

        <div
          style={{
            padding: 10,
            marginBottom: 18,
            border: '1px solid rgba(255,214,10,0.2)',
            background: 'rgba(255,214,10,0.04)',
            borderRadius: 4,
            fontSize: 8,
            lineHeight: 1.6,
            color: '#9aa5b1',
          }}
        >
          Simulation mode only. These events are synthetic and do not
          modify files, processes, network settings, or persistence.
        </div>

        <div
          style={{
            fontSize: 8,
            color: 'var(--text-muted)',
            letterSpacing: '0.12em',
            marginBottom: 9,
          }}
        >
          SELECT THREAT SCENARIO
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 7,
            marginBottom: 20,
          }}
        >
          {THREATS.map(threat => {
            const active =
              selected === threat.id

            const color =
              COLORS[threat.severity]

            return (
              <button
                key={threat.id}
                onClick={() =>
                  setSelected(threat.id)
                }
                style={{
                  textAlign: 'left',
                  padding: 12,
                  borderRadius: 4,
                  cursor: 'pointer',
                  background: active
                    ? `${color}0d`
                    : 'rgba(255,255,255,0.015)',
                  border: `1px solid ${
                    active
                      ? `${color}80`
                      : 'rgba(255,255,255,0.06)'
                  }`,
                }}
              >
                <div
                  style={{
                    fontSize: 9,
                    fontWeight: 700,
                    color: active
                      ? color
                      : '#a3aebb',
                  }}
                >
                  {threat.label}
                </div>

                <div
                  style={{
                    marginTop: 5,
                    fontSize: 7,
                    color,
                  }}
                >
                  {threat.severity}
                </div>
              </button>
            )
          })}
        </div>

        <button
          onClick={simulate}
          disabled={!selected || running}
          style={{
            width: '100%',
            padding: 12,
            borderRadius: 4,
            border: 'none',
            cursor:
              selected && !running
                ? 'pointer'
                : 'not-allowed',
            background:
              selected && !running
                ? '#00bfff'
                : 'rgba(255,255,255,0.05)',
            color:
              selected && !running
                ? '#000'
                : '#7c8697',
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            fontSize: 10,
            letterSpacing: '0.12em',
          }}
        >
          {running
            ? 'GENERATING TELEMETRY...'
            : 'SIMULATE THREAT'}
        </button>
      </div>
    </div>
  )
}
