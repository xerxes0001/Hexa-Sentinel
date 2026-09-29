/**
 * HexaSentinel — Attack dropdown shown when an attacker node
 * on the globe is clicked.
 *
 * Shows the latest 2 attacks from that country plus a button
 * to open the full country attack-history page.
 */
import { SEVERITY_COLORS as SEV_COLOR } from '../../utils/severity.js'

function timeAgo(ts) {
  const s = Math.floor((Date.now() - new Date(ts)) / 1000)

  if (s < 60) {
    return `${s}s ago`
  }

  if (s < 3600) {
    return `${Math.floor(s / 60)}m ago`
  }

  return `${Math.floor(s / 3600)}h ago`
}

export default function AttackDropdown({
  countryCode,
  countryName,
  attacks,
  x,
  y,
  onClose,
  onViewHistory,
}) {
  const latest = attacks.slice(0, 2)

  return (
    <div
      onClick={e => e.stopPropagation()}
      style={{
        position: 'absolute',
        left: x,
        top: y,
        transform: 'translate(-50%, 12px)',
        width: 240,
        zIndex: 50,
        background: 'rgba(8,12,18,0.97)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 6,
        boxShadow: '0 8px 30px rgba(0,0,0,0.5)',
        animation: 'fadeIn 0.15s ease-out',
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 10px',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--text-primary)',
            fontWeight: 700,
            letterSpacing: 1,
          }}
        >
          📍 {countryName} ({countryCode})
        </span>

        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            fontSize: 11,
            padding: 0,
          }}
        >
          ✕
        </button>
      </div>

      <div style={{ padding: '8px 10px' }}>
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
            letterSpacing: 1,
            marginBottom: 6,
          }}
        >
          LATEST ATTACKS{' '}
          {attacks.length === 0 ? '' : `(${attacks.length} total)`}
        </div>

        {latest.length === 0 && (
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-muted)',
              padding: '4px 0',
            }}
          >
            No recorded attacks from this origin.
          </div>
        )}

        {latest.map(inc => (
          <div
            key={inc.id}
            style={{
              marginBottom: 6,
              paddingBottom: 6,
              borderBottom:
                '1px solid rgba(255,255,255,0.04)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                marginBottom: 2,
              }}
            >
              <span
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  background:
                    SEV_COLOR[inc.severity] ?? '#888',
                  flexShrink: 0,
                }}
              />

              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8,
                  fontWeight: 700,
                  color:
                    SEV_COLOR[inc.severity] ?? '#888',
                }}
              >
                {inc.severity}
              </span>

              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8,
                  color: 'var(--text-muted)',
                  marginLeft: 'auto',
                }}
              >
                {timeAgo(inc.timestamp)}
              </span>
            </div>

            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                color: 'var(--text-secondary)',
              }}
            >
              {inc.type?.replace(/_/g, ' ')} →{' '}
              {inc.victim?.name ?? inc.victim?.asn}
            </div>

            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 8,
                color: 'var(--text-muted)',
              }}
            >
              {inc.attacker?.asn} · {inc.prefix}
            </div>
          </div>
        ))}

        <button
          onClick={() => onViewHistory(countryCode)}
          style={{
            width: '100%',
            marginTop: 4,
            padding: '7px 0',
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            fontWeight: 700,
            letterSpacing: 1,
            background: 'rgba(0,255,136,0.08)',
            border: '1px solid rgba(0,255,136,0.3)',
            color: 'var(--accent-green)',
            borderRadius: 3,
            cursor: 'pointer',
          }}
        >
          VIEW FULL ATTACK HISTORY →
        </button>
      </div>
    </div>
  )
}
