import { VANTAGE_POINTS } from '../../data/vantagePoints.js'

export default function VantageMatrix({ incident }) {
  // HexaSentinel vantage-point matrix.
  // For real incidents, confirmedPoints may only contain 'RIPE-RIS Live'.
  // Show all 8 vantage points but mark real confirmations specially.
  const isReal = incident.isRealData
  const confirmedSet = new Set(incident.confirmedPoints ?? [])

  // confirmedPoints contains real named vantage points from hostToVantage()
  // e.g. 'RIPE-RIS-01 Amsterdam', 'RouteViews Oregon' — use directly.
  const effectiveConfirmed = confirmedSet

  const confirmedCount = effectiveConfirmed.size

  return (
    <div style={{ marginBottom: 16 }}>
      {/* HexaSentinel vantage-point summary */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 8,
          padding: '6px 10px',
          background: 'rgba(0,255,136,0.04)',
          borderRadius: 3,
          border: '1px solid rgba(0,255,136,0.1)',
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--text-secondary)',
          }}
        >
          {confirmedCount}/8 vantage points confirmed
        </span>

        {isReal && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#00ff88',
              letterSpacing: 1,
            }}
          >
            ● RIPE RIS LIVE FEED
          </span>
        )}
      </div>

      {VANTAGE_POINTS.map(vp => {
        const confirmed = effectiveConfirmed.has(vp)

        return (
          <div
            key={vp}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '5px 0',
              borderBottom: '1px solid var(--border-subtle)',
            }}
          >
            <div
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                flexShrink: 0,
                background: confirmed
                  ? 'var(--accent-green)'
                  : '#1a1a1a',
                boxShadow: confirmed
                  ? '0 0 4px var(--accent-green)'
                  : 'none',
              }}
            />

            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                color: confirmed
                  ? 'var(--text-secondary)'
                  : '#2a2a2a',
                flex: 1,
              }}
            >
              {vp}
            </span>

            {confirmed ? (
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8,
                  color: 'var(--accent-green)',
                  letterSpacing: 1,
                }}
              >
                CONFIRMED
              </span>
            ) : (
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8,
                  color: '#1a1a1a',
                }}
              >
                —
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}
