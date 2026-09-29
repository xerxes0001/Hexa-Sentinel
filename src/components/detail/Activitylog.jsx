import { useEffect, useRef } from 'react'
import { useSHYENStore } from '../../store/useSHYENStore.js'

const LEVELS = {
  ACTION: {
    color: 'var(--accent-blue)',
    bg: 'rgba(0,191,255,0.08)',
  },
  INFO: {
    color: 'var(--text-secondary)',
    bg: 'rgba(255,255,255,0.035)',
  },
  SUCCESS: {
    color: 'var(--accent-green)',
    bg: 'rgba(0,255,136,0.08)',
  },
  WARNING: {
    color: '#ffd60a',
    bg: 'rgba(255,214,10,0.08)',
  },
  ERROR: {
    color: '#ff2d55',
    bg: 'rgba(255,45,85,0.08)',
  },
}

function timeLabel(ts) {
  if (!ts) return '--:--:--'

  const date = new Date(ts)

  if (Number.isNaN(date.getTime())) {
    return '--:--:--'
  }

  return date.toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export default function ActivityLog() {
  const entries = useSHYENStore(s => s.activityLog ?? [])
  const ref = useRef(null)

  // Keep the newest activity visible.
  useEffect(() => {
    if (ref.current) {
      ref.current.scrollTop = ref.current.scrollHeight
    }
  }, [entries.length])

  return (
    <div
      style={{
        border: '1px solid var(--border-subtle)',
        borderRadius: 4,
        background: 'rgba(10,15,25,0.45)',
        marginBottom: 16,
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          height: 34,
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 10px',
        }}
      >
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
            letterSpacing: '0.15em',
          }}
        >
          HEXASENTINEL ACTIVITY LOG
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <div
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--accent-green)',
              boxShadow: '0 0 7px var(--accent-green)',
              animation: 'dotBounce 1.4s ease-in-out infinite',
            }}
          />

          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--accent-green)',
              letterSpacing: '0.1em',
            }}
          >
            LIVE
          </span>
        </div>
      </div>

      {/* Activity stream */}
      <div
        ref={ref}
        style={{
          maxHeight: 190,
          overflowY: 'auto',
          padding: 8,
        }}
      >
        {entries.length === 0 ? (
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
            WAITING FOR SECURITY EVENTS...
          </div>
        ) : (
          entries.map(entry => {
            const level =
              LEVELS[entry.level] ??
              LEVELS.INFO

            return (
              <div
                key={entry.id}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '58px 64px 1fr',
                  gap: 8,
                  alignItems: 'baseline',
                  padding: '6px 7px',
                  borderBottom:
                    '1px solid rgba(255,255,255,0.035)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8,
                }}
              >
                {/* Timestamp */}
                <span
                  style={{
                    color: 'var(--text-muted)',
                  }}
                >
                  {timeLabel(entry.timestamp)}
                </span>

                {/* Level */}
                <span
                  style={{
                    color: level.color,
                    background: level.bg,
                    border: `1px solid ${level.color}33`,
                    borderRadius: 2,
                    padding: '1px 5px',
                    textAlign: 'center',
                    fontWeight: 700,
                  }}
                >
                  {entry.level ?? 'INFO'}
                </span>

                {/* Message */}
                <span
                  style={{
                    color:
                      entry.level === 'INFO'
                        ? 'var(--text-secondary)'
                        : 'var(--text-primary)',
                    lineHeight: 1.45,
                    wordBreak: 'break-word',
                  }}
                >
                  {entry.message}
                </span>
              </div>
            )
          })
        )}
      </div>

      {/* Footer */}
      <div
        style={{
          borderTop: '1px solid rgba(255,255,255,0.035)',
          padding: '5px 10px',
          display: 'flex',
          justifyContent: 'space-between',
          fontFamily: 'var(--font-mono)',
          fontSize: 7,
          color: 'var(--text-muted)',
          letterSpacing: '0.08em',
        }}
      >
        <span>EVENTS: {entries.length}</span>
        <span>LOCAL SECURITY MONITOR</span>
      </div>
    </div>
  )
}
