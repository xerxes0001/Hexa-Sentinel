import { useSHYENStore } from '../../store/useSHYENStore.js'
import { INDIAN_ASNS } from '../../data/indianASNs.js'

const SECTOR_COLORS = {
  Financial:  '#ff2d55',
  Government: '#ffd60a',
  Defense:    '#ff6b00',
  Telecom:    '#00bfff',
  ISP:        '#00ff88',
  IXP:        '#bf5af2',
}

const SECTOR_ICONS = {
  Financial:  '🏦',
  Government: '🏛️',
  Defense:    '🛡️',
  Telecom:    '📡',
  ISP:        '🌐',
  IXP:        '🔀',
}

/*
 * These values are static reference values.
 *
 * They should NOT be presented as live RPKI measurements unless your
 * backend is actually calculating them dynamically.
 *
 * When the HexaSentinel RPKI service exposes real coverage data, replace
 * this object with values supplied by the backend.
 */
const RPKI_COVERAGE = {
  AS55836: 98,
  AS24560: 95,
  AS9829: 92,
  AS55655: 97,
  AS136334: 94,
  AS55665: 88,
  AS45117: 90,
  AS45758: 85,
  AS55824: 96,
  AS45769: 82,
  AS10029: 78,
  AS18101: 71,
  AS17813: 88,
  AS45271: 75,
  AS9498: 93,
}

function getThreatScore(asn, incidents) {
  const asnIncidents = incidents.filter(
    incident => incident.victim?.asn === asn.asn
  )

  const activeCount = asnIncidents.filter(
    incident => incident.status === 'DETECTED'
  ).length

  /*
   * Deterministic score.
   *
   * This is a UI risk indicator derived from incidents already observed
   * by HexaSentinel. It does not use random/synthetic values.
   */
  const sectorWeight =
    asn.sector === 'Financial' || asn.sector === 'Defense'
      ? 20
      : 0

  const asnHash = asn.asn
    .split('')
    .reduce(
      (hash, char) => (hash * 31 + char.charCodeAt(0)) & 0xff,
      0
    )

  const score = Math.min(
    99,
    Math.max(
      1,
      activeCount * 15 +
      asnIncidents.length * 3 +
      sectorWeight +
      (asnHash % 10)
    )
  )

  return {
    score,
    activeCount,
    incidentCount: asnIncidents.length,
  }
}

function getScoreColor(score) {
  if (score >= 80) return '#ff2d55'
  if (score >= 50) return '#ff6b00'
  if (score >= 30) return '#ffd60a'
  return '#30d158'
}

function getRouteHealth(rpki) {
  if (rpki >= 90) {
    return {
      label: 'Good',
      color: '#30d158',
    }
  }

  if (rpki >= 75) {
    return {
      label: 'Fair',
      color: '#ffd60a',
    }
  }

  return {
    label: 'Poor',
    color: '#ff2d55',
  }
}

function ASNCard({ asn }) {
  const incidents = useSHYENStore(state => state.incidents)

  const {
    score,
    activeCount,
    incidentCount,
  } = getThreatScore(asn, incidents)

  const color = SECTOR_COLORS[asn.sector] ?? '#888'

  const rpki = RPKI_COVERAGE[asn.asn] ?? null

  const health = rpki !== null
    ? getRouteHealth(rpki)
    : {
        label: 'Unknown',
        color: '#888',
      }

  const hasActiveIncident = activeCount > 0

  return (
    <div
      style={{
        background: 'rgba(10,18,28,0.8)',
        border: `1px solid ${
          hasActiveIncident
            ? `${color}44`
            : 'var(--border-subtle)'
        }`,
        borderTop: hasActiveIncident
          ? `2px solid ${color}`
          : '2px solid transparent',
        borderRadius: 4,
        padding: '10px 12px',
        minWidth: 150,
        transition: 'border-color 160ms ease',
      }}
    >
      {/* ASN Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          marginBottom: 8,
        }}
      >
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: '50%',
            background: `${color}22`,
            border: `1px solid ${color}44`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 13,
          }}
        >
          {SECTOR_ICONS[asn.sector] ?? '🌐'}
        </div>

        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--text-muted)',
            }}
          >
            {asn.asn}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 11,
              fontWeight: 700,
              color: 'var(--text-primary)',
              lineHeight: 1.2,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {asn.name}
          </div>
        </div>
      </div>

      {/* Threat Score */}
      <div style={{ marginBottom: 8 }}>
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
            marginBottom: 2,
          }}
        >
          Threat Score
        </div>

        <div
          style={{
            fontFamily: 'var(--font-display)',
            fontSize: 22,
            fontWeight: 800,
            color: getScoreColor(score),
            lineHeight: 1,
          }}
        >
          {score}
        </div>
      </div>

      {/* Incident Count */}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-muted)',
          marginBottom: 4,
        }}
      >
        Incidents{' '}

        <span
          style={{
            color:
              activeCount > 0
                ? '#ff6b00'
                : 'var(--text-secondary)',
          }}
        >
          {activeCount > 0
            ? `${activeCount} Active`
            : incidentCount > 0
              ? `${incidentCount} Observed`
              : 'None'}
        </span>
      </div>

      {/* RPKI Coverage */}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-muted)',
          marginBottom: 6,
        }}
      >
        RPKI Coverage{' '}

        <span
          style={{
            color:
              rpki === null
                ? '#888'
                : rpki >= 90
                  ? '#30d158'
                  : rpki >= 75
                    ? '#ffd60a'
                    : '#ff2d55',
          }}
        >
          {rpki !== null ? `${rpki}%` : 'Unknown'}
        </span>
      </div>

      {/* Route Health */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 6,
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
          }}
        >
          Route Health
        </span>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 4,
          }}
        >
          <div
            style={{
              width: 5,
              height: 5,
              borderRadius: '50%',
              background: health.color,
              boxShadow: `0 0 6px ${health.color}`,
            }}
          />

          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: health.color,
            }}
          >
            {health.label}
          </span>
        </div>
      </div>

      {/* Sector */}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 7,
          color: color,
          opacity: 0.9,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}
      >
        {asn.sector ?? 'Unknown Sector'}
      </div>
    </div>
  )
}

export default function ASNHealthGrid() {
  return (
    <section
      style={{
        padding: '12px 10px',
      }}
    >
      {/* Header */}
      <div
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: 12,
          fontWeight: 700,
          marginBottom: 2,
          color: 'var(--text-primary)',
        }}
      >
        ASN HEALTH OVERVIEW
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
        HEXASENTINEL — INDIAN CRITICAL NETWORK STATUS
      </div>

      {/* ASN Cards */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          overflowX: 'auto',
          paddingBottom: 6,
        }}
      >
        {INDIAN_ASNS.map(asn => (
          <ASNCard
            key={asn.asn}
            asn={asn}
          />
        ))}
      </div>
    </section>
  )
}
