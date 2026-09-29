import { useSHYENStore } from '../../store/useSHYENStore.js'
import { useUptime } from '../../hooks/useUptime.js'

const STATUS_COLORS = {
  connected: '#00ff88',
  connecting: '#ffd60a',
  disconnected: '#666',
  error: '#ff2d55',
}

const VANTAGE_CITIES = [
  'Amsterdam',
  'Frankfurt',
  'London',
  'New York',
  'Singapore',
  'Tokyo',
  'Sydney',
  'Mumbai',
]

export default function Footer() {
  const risStatus = useSHYENStore(s => s.risStatus)
  const systemTime = useSHYENStore(s => s.systemTime)

  const color = STATUS_COLORS[risStatus] ?? '#666'

  // HexaSentinel uptime — updates every second and uses
  // the shared uptime formatter for accurate d/h/m/s display.
  const uptimeStr = useUptime()

  const lastUpdate = new Date(systemTime)
  const secAgo = Math.max(
    0,
    Math.floor(
      (Date.now() - lastUpdate.getTime()) / 1000
    )
  )

  return (
    <div
      style={{
        height: 28,
        borderTop: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        flexShrink: 0,
        background: '#050c14',
        fontFamily: 'var(--font-mono)',
        fontSize: 8,
      }}
    >
      {/* Left — HexaSentinel system status */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 14,
        }}
      >
        <Pill
          label="System Status"
          value="Healthy"
          color="#00ff88"
          dot
        />

        <Pill
          label="Data Feed"
          value="Live"
          color="#00ff88"
          dot
        />

        <Pill
          label="Last Update"
          value={`${secAgo}s ago`}
          color="var(--text-muted)"
        />

        <Pill
          label="Uptime"
          value={uptimeStr}
          color="var(--text-muted)"
        />
      </div>

      {/* Right — Global BGP vantage points */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <span
          style={{
            color: 'var(--text-muted)',
            letterSpacing: 1,
            marginRight: 4,
          }}
        >
          Global Vantage Points:
        </span>

        {VANTAGE_CITIES.map(city => (
          <span
            key={city}
            style={{
              color: '#2a3a4a',
              letterSpacing: 0.5,
            }}
          >
            {city}
          </span>
        ))}

        <span style={{ color: '#1a2a3a' }}>›</span>
      </div>
    </div>
  )
}

function Pill({ label, value, color, dot }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 5,
      }}
    >
      {dot && (
        <div
          style={{
            width: 5,
            height: 5,
            borderRadius: '50%',
            background: color,
            boxShadow: `0 0 4px ${color}`,
          }}
        />
      )}

      <span
        style={{
          color: 'var(--text-muted)',
          letterSpacing: 1,
        }}
      >
        {label}
      </span>

      <span
        style={{
          color,
          letterSpacing: 1,
        }}
      >
        {value}
      </span>
    </div>
  )
}
