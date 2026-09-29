/**
 * HexaSentinel — Threat Impact
 *
 * Endpoint equivalent of the old SnapShield "Blast Radius" panel.
 *
 * Instead of BGP propagation, this visualizes:
 *   - suspicious processes
 *   - affected files
 *   - network connections
 *   - persistence mechanisms
 */

import { useMemo, useState } from 'react'
import {
  analyzeThreatImpact,
  getImpactColor,
} from '../../engine/threatImpactEngine.js'

function ImpactBar({ value, max, color, label, detail }) {
  const percentage = max > 0
    ? Math.min(100, Math.round((value / max) * 100))
    : 0

  return (
    <div style={{ marginBottom: 12 }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          marginBottom: 5,
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-secondary)',
            letterSpacing: '0.04em',
          }}
        >
          {label}
        </span>

        <span
          style={{
            fontFamily: 'var(--font-display)',
            fontSize: 12,
            fontWeight: 800,
            color,
          }}
        >
          {value}
        </span>
      </div>

      <div
        style={{
          width: '100%',
          height: 8,
          background: 'rgba(255,255,255,0.06)',
          borderRadius: 4,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${percentage}%`,
            height: '100%',
            background: color,
            transition: 'width 0.5s ease',
          }}
        />
      </div>

      {detail && (
        <div
          style={{
            marginTop: 3,
            fontFamily: 'var(--font-mono)',
            fontSize: 7,
            color: 'var(--text-muted)',
          }}
        >
          {detail}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ label, color }) {
  return (
    <span
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 7,
        color,
        border: `1px solid ${color}55`,
        background: `${color}0d`,
        borderRadius: 2,
        padding: '2px 5px',
      }}
    >
      {label}
    </span>
  )
}

function ProcessRow({ process }) {
  const color = getImpactColor(process.severity)

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 70px 65px',
        gap: 8,
        alignItems: 'center',
        padding: '8px 9px',
        marginBottom: 4,
        background: 'rgba(255,255,255,0.018)',
        border: '1px solid rgba(255,255,255,0.04)',
        borderRadius: 3,
      }}
    >
      <div>
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8.5,
            color: process.suspicious
              ? '#ff6b00'
              : 'var(--text-primary)',
          }}
        >
          {process.name}
        </div>

        {process.path && (
          <div
            style={{
              marginTop: 2,
              fontFamily: 'var(--font-mono)',
              fontSize: 7,
              color: 'var(--text-muted)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {process.path}
          </div>
        )}
      </div>

      <span
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 7,
          color: 'var(--text-muted)',
        }}
      >
        PID {process.pid ?? '—'}
      </span>

      <StatusBadge
        label={process.severity ?? 'LOW'}
        color={color}
      />
    </div>
  )
}

function FileRow({ file }) {
  const severity = String(file.severity ?? 'LOW').toUpperCase()
  const color = getImpactColor(severity)

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        gap: 10,
        padding: '7px 9px',
        borderBottom: '1px solid rgba(255,255,255,0.035)',
      }}
    >
      <div
        style={{
          minWidth: 0,
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-primary)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {file.path ?? file.name ?? 'Unknown file'}
      </div>

      <StatusBadge label={severity} color={color} />
    </div>
  )
}

function NetworkRow({ connection }) {
  const blocked = !!connection.blocked

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 90px 55px',
        gap: 8,
        padding: '7px 9px',
        borderBottom: '1px solid rgba(255,255,255,0.035)',
        alignItems: 'center',
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-primary)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {connection.remote ?? connection.domain ?? 'Unknown destination'}
      </div>

      <span
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 7,
          color: 'var(--text-muted)',
        }}
      >
        {connection.protocol ?? 'UNKNOWN'}
      </span>

      <StatusBadge
        label={blocked ? 'BLOCKED' : 'OPEN'}
        color={blocked ? '#30d158' : '#ffd60a'}
      />
    </div>
  )
}

export default function ThreatImpact({ incident }) {
  const [tab, setTab] = useState('overview')

  const result = useMemo(
    () => analyzeThreatImpact(incident),
    [incident]
  )

  const impactColor = result.color

  return (
    <div
      style={{
        marginBottom: 16,
        border: '1px solid var(--border-subtle)',
        borderRadius: 4,
        background: 'rgba(10,15,25,0.45)',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '10px 12px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--text-muted)',
              letterSpacing: '0.14em',
            }}
          >
            THREAT IMPACT
          </div>

          <div
            style={{
              marginTop: 3,
              fontFamily: 'var(--font-display)',
              fontSize: 15,
              fontWeight: 800,
              color: 'var(--text-primary)',
            }}
          >
            Endpoint Exposure Assessment
          </div>
        </div>

        <div
          style={{
            textAlign: 'right',
          }}
        >
          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 22,
              fontWeight: 900,
              color: impactColor,
              lineHeight: 1,
            }}
          >
            {result.score}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 7,
              color: impactColor,
              letterSpacing: '0.1em',
              marginTop: 3,
            }}
          >
            {result.level}
          </div>
        </div>
      </div>

      {/* Summary */}
      <div
        style={{
          padding: '10px 12px',
          background: `${impactColor}08`,
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
          }}
        >
          HexaSentinel assessed the potential endpoint impact using observed
          process, file, network and persistence telemetry.
        </div>
      </div>

      {/* Tabs */}
      <div
        style={{
          display: 'flex',
          gap: 5,
          padding: '8px 10px',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        {[
          ['overview', 'OVERVIEW'],
          ['processes', 'PROCESSES'],
          ['files', 'FILES'],
          ['network', 'NETWORK'],
        ].map(([id, label]) => {
          const active = tab === id

          return (
            <button
              key={id}
              onClick={() => setTab(id)}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 7.5,
                padding: '5px 9px',
                cursor: 'pointer',
                borderRadius: 2,
                background: active
                  ? 'rgba(0,191,255,0.1)'
                  : 'transparent',
                border: `1px solid ${
                  active
                    ? 'rgba(0,191,255,0.45)'
                    : 'var(--border-mid)'
                }`,
                color: active
                  ? 'var(--accent-blue)'
                  : 'var(--text-muted)',
              }}
            >
              {label}
            </button>
          )
        })}
      </div>

      {/* Content */}
      <div style={{ padding: 12 }}>
        {tab === 'overview' && (
          <>
            <ImpactBar
              value={result.processCount}
              max={10}
              color="#ff6b00"
              label="SUSPICIOUS PROCESSES"
              detail="Observed processes requiring behavioral review"
            />

            <ImpactBar
              value={result.fileCount}
              max={20}
              color="#ff2d55"
              label="AFFECTED FILES"
              detail="Files associated with the current threat"
            />

            <ImpactBar
              value={result.connectionCount}
              max={10}
              color="#00bfff"
              label="NETWORK CONNECTIONS"
              detail="Observed remote communication"
            />

            <ImpactBar
              value={result.persistenceCount}
              max={5}
              color="#bf5af2"
              label="PERSISTENCE EVENTS"
              detail="Startup or persistence mechanisms detected"
            />

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 6,
                marginTop: 8,
              }}
            >
              <div
                style={{
                  padding: 9,
                  background: 'rgba(255,255,255,0.025)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  borderRadius: 3,
                }}
              >
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 7,
                    color: 'var(--text-muted)',
                  }}
                >
                  QUARANTINE
                </div>

                <div
                  style={{
                    marginTop: 4,
                    fontFamily: 'var(--font-display)',
                    fontSize: 12,
                    fontWeight: 800,
                    color: result.containment.quarantined
                      ? '#30d158'
                      : '#ffd60a',
                  }}
                >
                  {result.containment.quarantined
                    ? 'ACTIVE'
                    : 'NOT ACTIVE'}
                </div>
              </div>

              <div
                style={{
                  padding: 9,
                  background: 'rgba(255,255,255,0.025)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  borderRadius: 3,
                }}
              >
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 7,
                    color: 'var(--text-muted)',
                  }}
                >
                  NETWORK BLOCK
                </div>

                <div
                  style={{
                    marginTop: 4,
                    fontFamily: 'var(--font-display)',
                    fontSize: 12,
                    fontWeight: 800,
                    color: result.containment.blocked
                      ? '#30d158'
                      : '#ffd60a',
                  }}
                >
                  {result.containment.blocked
                    ? 'ACTIVE'
                    : 'NOT ACTIVE'}
                </div>
              </div>
            </div>
          </>
        )}

        {tab === 'processes' && (
          <div>
            {result.processTree.length === 0 ? (
              <EmptyState text="NO PROCESS TELEMETRY AVAILABLE" />
            ) : (
              result.processTree.map((process, index) => (
                <ProcessRow
                  key={process.pid ?? `${process.name}-${index}`}
                  process={process}
                />
              ))
            )}
          </div>
        )}

        {tab === 'files' && (
          <div>
            {result.affectedFiles.length === 0 ? (
              <EmptyState text="NO FILE TELEMETRY AVAILABLE" />
            ) : (
              result.affectedFiles.map((file, index) => (
                <FileRow
                  key={file.path ?? file.name ?? index}
                  file={file}
                />
              ))
            )}
          </div>
        )}

        {tab === 'network' && (
          <div>
            {result.networkActivity.length === 0 ? (
              <EmptyState text="NO NETWORK TELEMETRY AVAILABLE" />
            ) : (
              result.networkActivity.map((connection, index) => (
                <NetworkRow
                  key={`${connection.remote ?? 'remote'}-${index}`}
                  connection={connection}
                />
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function EmptyState({ text }) {
  return (
    <div
      style={{
        padding: '22px 10px',
        textAlign: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: 8,
        color: 'var(--text-muted)',
        letterSpacing: '0.08em',
      }}
    >
      {text}
    </div>
  )
}
