import { useHexaSentinelStore } from '../../store/useHexaSentinelStore.js'

const ATTACK_TYPES = ['Route Leak', 'Origin Hijack', 'Subprefix Hijack']
const CONF_LEVELS = ['Low', 'Medium', 'High', 'Critical']

const SEV_BG = {
  0: 'rgba(255,255,255,0.03)',
  1: 'rgba(48,209,88,0.15)',
  2: 'rgba(255,214,10,0.15)',
  3: 'rgba(255,107,0,0.2)',
  4: 'rgba(255,45,85,0.25)',
  5: 'rgba(255,45,85,0.35)',
  6: 'rgba(255,45,85,0.5)',
  7: 'rgba(255,45,85,0.6)',
  8: 'rgba(255,45,85,0.75)',
  9: 'rgba(255,45,85,0.9)',
}

const SEV_TEXT = (n) =>
  n === 0
    ? '#333'
    : n < 3
      ? '#30d158'
      : n < 6
        ? '#ffd60a'
        : '#ff2d55'

export default function AttackHeatmap() {
  const incidents = useHexaSentinelStore(s => s.incidents)

  // Build matrix: [attackType][confLevel] = count
  const matrix = {}

  for (const type of ATTACK_TYPES) {
    matrix[type] = {
      Low: 0,
      Medium: 0,
      High: 0,
      Critical: 0,
    }
  }

  for (const inc of incidents) {
    const type =
      inc.type === 'ORIGIN_HIJACK'
        ? 'Origin Hijack'
        : inc.type === 'SUBPREFIX_HIJACK'
          ? 'Subprefix Hijack'
          : inc.type === 'ROUTE_LEAK'
            ? 'Route Leak'
            : null

    if (!type) continue

    const conf =
      inc.confidence >= 90
        ? 'Critical'
        : inc.confidence >= 75
          ? 'High'
          : inc.confidence >= 60
            ? 'Medium'
            : 'Low'

    matrix[type][conf]++
  }

  return (
    <div style={{ padding: '12px 10px' }}>
      <div
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: 12,
          fontWeight: 700,
          marginBottom: 2,
        }}
      >
        HEXASENTINEL BGP ATTACK HEATMAP
      </div>

      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-muted)',
          marginBottom: 10,
          letterSpacing: '0.05em',
        }}
      >
        HexaSentinel attack types by detection confidence
      </div>

      {/* Column headers */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '90px repeat(4, 1fr)',
          gap: 3,
          marginBottom: 4,
        }}
      >
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 7,
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'flex-end',
            paddingBottom: 2,
          }}
        >
          Detection Confidence →
        </div>

        {CONF_LEVELS.map(confidence => (
          <div
            key={confidence}
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--text-muted)',
              textAlign: 'center',
              letterSpacing: '0.05em',
            }}
          >
            {confidence}
          </div>
        ))}
      </div>

      {/* Rows */}
      {ATTACK_TYPES.map(type => (
        <div
          key={type}
          style={{
            display: 'grid',
            gridTemplateColumns: '90px repeat(4, 1fr)',
            gap: 3,
            marginBottom: 3,
          }}
        >
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              letterSpacing: '0.03em',
            }}
          >
            {type}
          </div>

          {CONF_LEVELS.map(confidence => {
            const count = matrix[type][confidence]

            return (
              <div
                key={confidence}
                style={{
                  height: 28,
                  borderRadius: 3,
                  background: SEV_BG[Math.min(count, 9)],
                  border: '1px solid rgba(255,255,255,0.05)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    fontWeight: 700,
                    color: SEV_TEXT(count),
                  }}
                >
                  {count}
                </span>
              </div>
            )
          })}
        </div>
      ))}

      {/* Impact axis label */}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 7,
          color: 'var(--text-muted)',
          marginTop: 4,
          textAlign: 'right',
        }}
      >
        ← Impact
      </div>
    </div>
  )
}
