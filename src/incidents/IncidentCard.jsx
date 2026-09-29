import { useState } from 'react'
import { useHexaSentinelStore } from '../../store/useHexaSentinelStore.js'
import PulseRing from '../shared/PulseRing.jsx'
import SeverityBadge from '../shared/SeverityBadge.jsx'
import Tag from '../shared/Tag.jsx'

const SEV_COLOR = {
  CRITICAL: 'var(--accent-red)',
  HIGH: 'var(--accent-orange)',
  MEDIUM: 'var(--accent-amber)',
  LOW: '#30d158',
}

function elapsedStr(ts, now) {
  const s = Math.floor((now - new Date(ts)) / 1000)

  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`

  return `${Math.floor(s / 3600)}h ago`
}

// Feature 7 — RPKI lock icon on card
function RPKILock({ rpkiStatus }) {
  if (!rpkiStatus) return null

  const color = rpkiStatus.valid
    ? '#30d158'
    : rpkiStatus.invalid
      ? '#ff2d55'
      : '#ffd60a'

  const icon = rpkiStatus.valid ? '🔒' : '🔓'

  const label = rpkiStatus.valid
    ? 'RPKI OK'
    : rpkiStatus.invalid
      ? 'NO RPKI'
      : 'RPKI?'

  return (
    <span
      title={`RPKI: ${rpkiStatus.state}`}
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 8,
        color,
        border: `1px solid ${color}44`,
        borderRadius: 2,
        padding: '1px 4px',
        letterSpacing: '0.05em',
      }}
    >
      {icon} {label}
    </span>
  )
}

export default function IncidentCard({
  incident: inc,
  selected,
  onClick,
  onAction,
}) {
  // Shared HexaSentinel system clock.
  // This avoids individual timers on every incident card.
  const systemTime = useHexaSentinelStore(
    s => s.systemTime
  )

  const color =
    SEV_COLOR[inc.severity] ?? '#30d158'

  const active =
    inc.status === 'DETECTED'

  const flagMap = {
    IN: '🇮🇳',
    CN: '🇨🇳',
    PK: '🇵🇰',
    EG: '🇪🇬',
    DE: '🇩🇪',
    IT: '🇮🇹',
    US: '🇺🇸',
    AU: '🇦🇺',
    JP: '🇯🇵',
    RU: '🇷🇺',
    GB: '🇬🇧',
    NL: '🇳🇱',
    FR: '🇫🇷',
    BR: '🇧🇷',
    SG: '🇸🇬',
    KR: '🇰🇷',
    CA: '🇨🇦',
    ZA: '🇿🇦',
    ID: '🇮🇩',
    VN: '🇻🇳',
    TH: '🇹🇭',
    UA: '🇺🇦',
    PL: '🇵🇱',
    ES: '🇪🇸',
    SE: '🇸🇪',
    CH: '🇨🇭',
    TR: '🇹🇷',
    HK: '🇭🇰',
    TW: '🇹🇼',
    MX: '🇲🇽',
    AE: '🇦🇪',
    SA: '🇸🇦',
    IR: '🇮🇷',
    BD: '🇧🇩',
    NG: '🇳🇬',
    RO: '🇷🇴',
  }

  const attackerFlag =
    flagMap[inc.attacker?.country] || '🌐'

  return (
    <div
      onClick={onClick}
      style={{
        padding: 12,
        marginBottom: 6,
        background: selected
          ? 'rgba(15,25,40,0.95)'
          : 'var(--bg-card)',

        borderTop:
          `1px solid ${
            selected
              ? color + '80'
              : 'var(--border-subtle)'
          }`,

        borderRight:
          `1px solid ${
            selected
              ? color + '80'
              : 'var(--border-subtle)'
          }`,

        borderBottom:
          `1px solid ${
            selected
              ? color + '80'
              : 'var(--border-subtle)'
          }`,

        borderLeft:
          `3px solid ${color}`,

        borderRadius: 4,
        cursor: 'pointer',
        transition: 'all 0.2s',
        animation: 'slideIn 0.3s ease-out',
      }}
    >
      {/* Row 1 — badges + time */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 5,
          marginBottom: 7,
          flexWrap: 'wrap',
        }}
      >
        <PulseRing
          color={color}
          size={7}
          active={active}
        />

        <SeverityBadge
          severity={inc.severity}
        />

        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
          }}
        >
          #{String(inc.id).padStart(4, '0')}
        </span>

        {inc.isRealData && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#00ff88',
              border: '1px solid #00ff8844',
              borderRadius: 2,
              padding: '1px 4px',
            }}
          >
            ● LIVE
          </span>
        )}

        {inc.isSimulated && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#bf5af2',
              border: '1px solid #bf5af244',
              borderRadius: 2,
              padding: '1px 4px',
            }}
          >
            ⚡ SIM
          </span>
        )}

        {inc.coordinatedAttack && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#ff2d55',
              border: '1px solid #ff2d5566',
              borderRadius: 2,
              padding: '1px 4px',
              animation:
                'glowPulse 1.5s ease-in-out infinite',
            }}
          >
            ⚠ CT+BGP
          </span>
        )}

        {inc.isRepeatAttacker && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#ff6b00',
              border: '1px solid #ff6b0044',
              borderRadius: 2,
              padding: '1px 4px',
            }}
          >
            ↻ REPEAT
          </span>
        )}

        {inc.aiAnalyzing && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#00bfff',
              animation:
                'termBlink 1s ease infinite',
            }}
          >
            ◈ AI...
          </span>
        )}

        {inc.aiDecided && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: '#00bfff',
              border: '1px solid #00bfff44',
              borderRadius: 2,
              padding: '1px 4px',
            }}
          >
            ◈ AI ACTED
          </span>
        )}

        {/* RPKI status */}
        <RPKILock
          rpkiStatus={inc.rpkiStatus}
        />

        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
            marginLeft: 'auto',
          }}
        >
          {elapsedStr(
            inc.timestamp,
            systemTime
          )}
        </span>
      </div>

      {/* Row 2 — victim */}
      <div
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: 12,
          fontWeight: 700,
          marginBottom: 3,
          color: 'var(--text-primary)',
        }}
      >
        🇮🇳 {inc.victim?.name}

        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--text-muted)',
            fontWeight: 400,
            marginLeft: 6,
          }}
        >
          {inc.victim?.sector}
        </span>
      </div>

      {/* Row 3 — prefix + attacker */}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: 'var(--text-secondary)',
          marginBottom: 6,
        }}
      >
        {inc.prefix} ← {attackerFlag}{' '}
        {inc.attacker?.asn}

        {inc.attacker?.country &&
          inc.attacker.country !== '??' &&
          ` [${inc.attacker.country}]`}

        {inc.pathAnomaly && (
          <span
            style={{
              color: '#ff6b00',
              marginLeft: 6,
            }}
          >
            ⚠ {inc.pathAnomaly}
          </span>
        )}
      </div>

      {/* Row 4 — tags */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 4,
          marginBottom: active ? 8 : 0,
        }}
      >
        <Tag color={color}>
          {inc.type?.replace(/_/g, ' ')}
        </Tag>

        <Tag color="var(--accent-blue)">
          {inc.confirmedPoints?.length ?? 0}/8 VPs
        </Tag>

        <Tag color="var(--text-secondary)">
          {inc.confidence}% CONF
        </Tag>

        {inc.status === 'MITIGATED' && (
          <Tag color="#30d158">
            ✓ MITIGATED
          </Tag>
        )}
      </div>

      {/* Row 5 — HexaSentinel countermeasure status */}
      {active && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            flexWrap: 'wrap',
          }}
        >
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              letterSpacing: 0.5,
              color:
                inc.countermeasuresReady
                  ? 'var(--accent-green)'
                  : 'var(--accent-amber)',
            }}
          >
            {inc.countermeasuresReady
              ? inc.isSimulated
                ? '✓ [DEMO] HEXASENTINEL COUNTERMEASURES READY — click for details'
                : '⚠ HEXASENTINEL COUNTERMEASURES READY — click for details'
              : '… HexaSentinel generating countermeasures'}
          </span>

          {inc.countermeasuresReady &&
            !inc.forensicsReady && (
              <ActionBtn
                color="var(--accent-purple)"
                onClick={e => {
                  e.stopPropagation()
                  onAction(
                    inc.id,
                    'forensics'
                  )
                }}
              >
                FORENSICS
              </ActionBtn>
            )}
        </div>
      )}
    </div>
  )
}

function ActionBtn({
  color,
  onClick,
  children,
}) {
  const [h, setH] = useState(false)

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 8,
        padding: '3px 8px',
        background: h ? color : 'none',
        border: `1px solid ${color}`,
        color: h ? '#000' : color,
        cursor: 'pointer',
        borderRadius: 2,
        letterSpacing: 0.5,
        transition: 'all 0.15s',
      }}
    >
      {children}
    </button>
  )
}
