import { useState } from 'react'
import { useSHYENStore } from '../../store/useSHYENStore.js'

const FORENSICS_ACTION = {
  key: 'forensics',
  field: 'forensicsReady',
  label: 'FORENSIC PACKAGE',
  color: 'var(--accent-purple)',
  desc: 'Auto-compile evidence bundle: origin AS, timestamp chain, vantage confirmations, affected prefix scope — formatted for CERT-In submission',
}

const ARTIFACTS = [
  {
    key: 'roa',
    label: 'RPKI ROA (RFC 6482)',
    color: 'var(--accent-blue)',
    desc: 'Route Origin Authorization — invalidates the hijacked origin claim',
  },
  {
    key: 'rtbh',
    label: 'RTBH BLACKHOLE (RFC 7999)',
    color: 'var(--accent-amber)',
    desc: 'Remotely-triggered blackhole community — null-routes the hijacked prefix at IXP route servers',
  },
  {
    key: 'flowspec',
    label: 'BGP FLOWSPEC (RFC 8955)',
    color: 'var(--accent-purple)',
    desc: 'Drop rule matching the confirmed hijacker AS path',
  },
  {
    key: 'moreSpecific',
    label: 'MORE-SPECIFIC ANNOUNCEMENT',
    color: 'var(--accent-green)',
    desc: 'Route deaggregation to win traffic back via longest-prefix-match — the technique Apple used against the 2022 Rostelecom hijack',
  },
]

// Format milliseconds → human readable
function formatMitigationTime(ms) {
  if (!ms || ms < 0) return null
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`

  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

function ArtifactBlock({ artifact, text }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
    } catch {}

    setCopied(true)
    setTimeout(() => setCopied(false), 1800)
  }

  return (
    <div
      style={{
        border: `1px solid ${artifact.color}40`,
        borderRadius: 4,
        marginBottom: 8,
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 12px',
          background: `${artifact.color}10`,
        }}
      >
        <div>
          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 10,
              fontWeight: 700,
              color: artifact.color,
              letterSpacing: 1,
            }}
          >
            {artifact.label}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--text-secondary)',
              marginTop: 2,
            }}
          >
            {artifact.desc}
          </div>
        </div>

        <button
          onClick={copy}
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            padding: '5px 10px',
            flexShrink: 0,
            marginLeft: 10,
            background: 'none',
            border: `1px solid ${artifact.color}60`,
            color: artifact.color,
            cursor: 'pointer',
            borderRadius: 2,
            letterSpacing: 1,
            whiteSpace: 'nowrap',
          }}
        >
          {copied ? '✓ COPIED' : 'COPY'}
        </button>
      </div>

      <pre
        style={{
          margin: 0,
          padding: '10px 12px',
          fontFamily: 'var(--font-mono)',
          fontSize: 8.5,
          color: 'var(--text-primary)',
          background: 'rgba(6,10,16,0.9)',
          lineHeight: 1.6,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          maxHeight: 160,
          overflowY: 'auto',
        }}
      >
        {text}
      </pre>
    </div>
  )
}

function ActionRow({
  action,
  incident,
  done,
  onExecute,
  executing,
}) {
  const isRunning = executing === action.key

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: 10,
        background: done
          ? 'rgba(0,255,136,0.04)'
          : 'rgba(10,14,20,0.6)',
        border: `1px solid ${
          done
            ? 'rgba(0,255,136,0.2)'
            : 'var(--border-subtle)'
        }`,
        borderRadius: 3,
        marginBottom: 6,
        transition: 'background 0.2s, border-color 0.2s',
      }}
    >
      <div
        style={{
          width: 20,
          height: 20,
          borderRadius: '50%',
          border: `1px solid ${
            done
              ? 'var(--accent-green)'
              : 'var(--border-mid)'
          }`,
          background: done
            ? 'rgba(0,255,136,0.1)'
            : 'none',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          fontSize: 10,
          color: done
            ? 'var(--accent-green)'
            : 'var(--text-muted)',
          transition: 'all 0.2s',
        }}
      >
        {done ? '✓' : isRunning ? '…' : '○'}
      </div>

      <div style={{ flex: 1 }}>
        <div
          style={{
            fontFamily: 'var(--font-display)',
            fontSize: 11,
            fontWeight: 700,
            color: action.color,
            marginBottom: 2,
          }}
        >
          {action.label}
        </div>

        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-secondary)',
            lineHeight: 1.5,
          }}
        >
          {action.desc}
        </div>
      </div>

      {done ? (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--accent-green)',
            letterSpacing: 1,
            whiteSpace: 'nowrap',
          }}
        >
          READY
        </span>
      ) : (
        onExecute && (
          <button
            onClick={onExecute}
            disabled={isRunning}
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              padding: '5px 10px',
              background: 'none',
              border: `1px solid ${action.color}60`,
              color: action.color,
              cursor: isRunning ? 'wait' : 'pointer',
              borderRadius: 2,
              letterSpacing: 1,
              whiteSpace: 'nowrap',
              opacity: isRunning ? 0.6 : 1,
            }}
          >
            {isRunning ? 'COMPILING...' : 'COMPILE'}
          </button>
        )
      )}
    </div>
  )
}

/*
 * HexaSentinel countermeasure panel.
 *
 * The panel generates RFC-format response artifacts for both:
 *   1. Real RIPE RIS detections
 *   2. HexaSentinel demo/simulation incidents
 *
 * HexaSentinel does not directly operate a BGP session, RPKI signing
 * authority, or IXP peering connection. Therefore these artifacts are
 * generated recommendations/configurations and are not represented as
 * network deployments.
 *
 * Demo incidents are clearly labeled as simulated.
 * Real incidents remain pending human NOC/network-operator authorization.
 */
export default function ResponseActions({ incident }) {
  const triggerAction = useSHYENStore(
    s => s.triggerAction
  )

  const [executing, setExecuting] = useState(null)

  const isDemo = !!incident.isSimulated
  const cm = incident.countermeasures

  const isMit =
    incident.status === 'MITIGATED'

  const mitTime =
    formatMitigationTime(incident.mitigationMs)

  async function compileForensics() {
    setExecuting('forensics')

    triggerAction(
      incident.id,
      'forensics'
    )

    await new Promise(resolve =>
      setTimeout(resolve, 80)
    )

    setExecuting(null)
  }

  if (!cm) {
    return (
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: 'var(--text-muted)',
          padding: '10px 0',
        }}
      >
        {isDemo
          ? '[DEMO] Generating HexaSentinel countermeasure artifacts…'
          : 'Generating HexaSentinel countermeasure artifacts…'}
      </div>
    )
  }

  return (
    <div style={{ marginBottom: 16 }}>
      {isMit ? (
        <div
          style={{
            padding: '12px 14px',
            background: 'rgba(0,255,136,0.06)',
            border:
              '1px solid rgba(0,255,136,0.3)',
            borderRadius: 4,
            marginBottom: 12,
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span
              style={{
                fontFamily:
                  'var(--font-display)',
                fontSize: 11,
                color:
                  'var(--accent-green)',
                letterSpacing: 1,
              }}
            >
              ✓ [DEMO] SIMULATED MITIGATION COMPLETE
            </span>

            {mitTime && (
              <span
                style={{
                  fontFamily:
                    'var(--font-mono)',
                  fontSize: 9,
                  color:
                    'var(--text-muted)',
                }}
              >
                TTM:{' '}
                <span
                  style={{
                    color:
                      'var(--accent-green)',
                  }}
                >
                  {mitTime}
                </span>
              </span>
            )}
          </div>

          <div
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 8,
              color:
                'var(--text-secondary)',
              marginTop: 4,
            }}
          >
            Countermeasures below were
            generated when the simulated
            attack was confirmed.
          </div>
        </div>
      ) : (
        <div
          style={{
            padding: '10px 14px',
            background: isDemo
              ? 'rgba(0,255,136,0.05)'
              : 'rgba(255,214,10,0.06)',
            border: `1px solid ${
              isDemo
                ? 'rgba(0,255,136,0.25)'
                : 'rgba(255,214,10,0.3)'
            }`,
            borderRadius: 4,
            marginBottom: 12,
          }}
        >
          <div
            style={{
              fontFamily:
                'var(--font-display)',
              fontSize: 10,
              letterSpacing: 1,
              marginBottom: 4,
              color: isDemo
                ? 'var(--accent-green)'
                : 'var(--accent-amber)',
            }}
          >
            {isDemo
              ? '✓ [DEMO] COUNTERMEASURES GENERATED FOR SIMULATED ATTACK'
              : '⚠ COUNTERMEASURES GENERATED — PENDING NOC AUTHORIZATION'}
          </div>

          <div
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 8,
              color:
                'var(--text-secondary)',
              lineHeight: 1.6,
            }}
          >
            {isDemo
              ? 'HexaSentinel generated these RFC-format artifacts for the simulated incident. No network deployment has occurred.'
              : 'HexaSentinel generated these RFC-format response artifacts. Deployment requires authorization from a human network operator.'}
          </div>
        </div>
      )}

      <ArtifactBlock
        artifact={ARTIFACTS[0]}
        text={cm.roa}
      />

      <ArtifactBlock
        artifact={ARTIFACTS[1]}
        text={cm.rtbh}
      />

      <ArtifactBlock
        artifact={ARTIFACTS[2]}
        text={cm.flowspec}
      />

      <ArtifactBlock
        artifact={ARTIFACTS[3]}
        text={cm.moreSpecific}
      />

      <ActionRow
        action={FORENSICS_ACTION}
        incident={incident}
        done={!!incident.forensicsReady}
        onExecute={compileForensics}
        executing={executing}
      />
    </div>
  )
}
