import { useSHYENStore } from '../../store/useSHYENStore.js'

const STAGES = [
  {
    key: 'detected',
    label: 'Anomaly\nDetected',
    icon: '🔍',
    color: '#ff6b00',
  },
  {
    key: 'validation',
    label: 'Multi-Vantage\nValidation',
    icon: '🔬',
    color: '#ffd60a',
  },
  {
    key: 'confirmed',
    label: 'Threat\nConfirmed',
    icon: '⚠️',
    color: '#ff2d55',
  },
  {
    key: 'rpki',
    label: 'RPKI\nInvalidation',
    icon: '🔒',
    color: '#00bfff',
  },
  {
    key: 'ixp',
    label: 'IXP Alerts\nDispatched',
    icon: '📡',
    color: '#00bfff',
  },
  {
    key: 'mitigation',
    label: 'Mitigation\nIn Progress',
    icon: '🛡️',
    color: '#30d158',
  },
]

function formatTime(ts, offsetMs) {
  const date = new Date(
    new Date(ts).getTime() + offsetMs
  )

  return date
    .toISOString()
    .replace('T', ' ')
    .slice(11, 19)
}

export default function OperationalTimeline() {
  const incidents = useSHYENStore(s => s.incidents)
  const inc = incidents[0]

  if (!inc) return null

  const stagesDone = {
    detected: true,
    validation: true,
    confirmed: inc.confidence >= 75,
    rpki: inc.rpkiPushed,
    ixp: inc.ixpAlerted,
    mitigation: inc.status === 'MITIGATED',
  }

  // HexaSentinel incident timeline:
  // estimated resolution is three minutes from detection.
  const estRes = new Date(
    new Date(inc.timestamp).getTime() + 3 * 60000
  )

  const estStr = estRes
    .toISOString()
    .replace('T', ' ')
    .slice(11, 19)

  // Determine the latest completed operational stage.
  const currentStage = (() => {
    let last = -1

    STAGES.forEach((stage, index) => {
      if (stagesDone[stage.key]) {
        last = index
      }
    })

    return last
  })()

  return (
    <div
      style={{
        borderTop: '1px solid var(--border-subtle)',
        background: '#070f18',
        padding: '10px 16px',
        flexShrink: 0,
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: 11,
          fontWeight: 700,
          marginBottom: 8,
        }}
      >
        OPERATIONAL TIMELINE
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 0,
        }}
      >
        {STAGES.map((stage, index) => {
          const done = stagesDone[stage.key]
          const current = index === currentStage

          const offsets = [
            0,
            3000,
            8000,
            12000,
            16000,
            22000,
          ]

          return (
            <div
              key={stage.key}
              style={{
                display: 'flex',
                alignItems: 'center',
                flex: 1,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 7,
                    color: 'var(--text-muted)',
                  }}
                >
                  {formatTime(
                    inc.timestamp,
                    offsets[index]
                  )}
                </div>

                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    background: done
                      ? `${stage.color}22`
                      : 'rgba(255,255,255,0.03)',
                    border: `1.5px solid ${
                      done
                        ? stage.color
                        : 'rgba(255,255,255,0.08)'
                    }`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 13,
                    boxShadow: current
                      ? `0 0 10px ${stage.color}66`
                      : 'none',
                    animation: current
                      ? 'pulse 2s ease infinite'
                      : 'none',
                  }}
                >
                  {stage.icon}
                </div>

                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 7,
                    color: done
                      ? stage.color
                      : 'var(--text-muted)',
                    textAlign: 'center',
                    whiteSpace: 'pre-line',
                    lineHeight: 1.4,
                  }}
                >
                  {stage.label}
                </div>
              </div>

              {index < STAGES.length - 1 && (
                <div
                  style={{
                    flex: 1,
                    height: 1.5,
                    background: stagesDone[
                      STAGES[index + 1].key
                    ]
                      ? stage.color
                      : 'rgba(255,255,255,0.06)',
                    margin: '0 4px',
                    marginBottom: 16,
                  }}
                />
              )}
            </div>
          )
        })}

        {/* Estimated resolution */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 4,
            marginLeft: 8,
          }}
        >
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 7,
              color: 'var(--text-muted)',
            }}
          >
            EST. RESOLUTION
          </div>

          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              background: 'rgba(48,209,88,0.1)',
              border:
                '1.5px solid rgba(48,209,88,0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
            }}
          >
            🏁
          </div>

          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 12,
              fontWeight: 800,
              color: '#30d158',
            }}
          >
            {estStr}
          </div>
        </div>
      </div>

      <style>
        {`
          @keyframes pulse {
            0%, 100% {
              opacity: 1;
            }

            50% {
              opacity: 0.4;
            }
          }
        `}
      </style>
    </div>
  )
}
