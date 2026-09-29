import { useSHYENStore } from '../../store/useSHYENStore.js'

const MIN_ENTRIES = 8 // ensure smooth loop

export default function BGPTicker() {
  const ticker = useSHYENStore(s => s.ticker)

  // Fallback entry while HexaSentinel establishes the live BGP feed
  const padded = ticker.length === 0
    ? [{
        text: 'HexaSentinel NPU monitoring Indian BGP space... connecting to RIPE RIS Live feed',
        suspicious: false,
        realData: false,
      }]
    : ticker

  // Duplicate for seamless loop
  const doubled = [...padded, ...padded]

  // Scale scroll speed with entry count — more entries = faster
  const duration = Math.max(
    20,
    Math.min(60, padded.length * 6)
  )

  return (
    <div
      style={{
        height: 28,
        background: 'rgba(6,10,16,0.9)',
        borderBottom: '1px solid var(--border-subtle)',
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        flexShrink: 0,
        position: 'relative',
      }}
    >
      {/* Label */}
      <div
        style={{
          position: 'absolute',
          left: 0,
          top: 0,
          bottom: 0,
          width: 88,
          background: 'rgba(0,255,136,0.08)',
          borderRight: '1px solid rgba(0,255,136,0.15)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--accent-green)',
          letterSpacing: 2,
          zIndex: 2,
          flexShrink: 0,
        }}
      >
        BGP FEED
      </div>

      <div
        style={{
          marginLeft: 88,
          overflow: 'hidden',
          flex: 1,
        }}
      >
        <div
          style={{
            display: 'flex',
            whiteSpace: 'nowrap',
            animation: `tickerScroll ${duration}s linear infinite`,
          }}
        >
          {doubled.map((entry, i) => (
            <span
              key={i}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                padding: '0 28px',
                color: entry.suspicious
                  ? 'var(--accent-red)'
                  : entry.isWithdrawal
                  ? '#5588ff'
                  : entry.realData
                  ? 'var(--accent-green)'
                  : '#446644',
              }}
            >
              {entry.suspicious
                ? '⚠ '
                : entry.isWithdrawal
                ? '↓ '
                : '● '}
              {entry.text}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
