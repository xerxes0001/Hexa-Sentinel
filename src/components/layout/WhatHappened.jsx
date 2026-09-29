/**
 * Feature 26 — "WHAT JUST HAPPENED" plain English panel
 * Always visible, updates on every new incident
 * Explains the latest event in plain English for non-technical judges
 */
import { useSHYENStore } from '../../store/useSHYENStore.js'

const SECTOR_IMPACT = {
  Financial:  'financial transactions may be at risk',
  Government: 'government communications may be exposed',
  Defense:    'defense network traffic may be intercepted',
  Telecom:    'telecom routing is being disrupted',
  ISP:        'internet service is being misdirected',
  IXP:        'internet exchange traffic is affected',
}

const ATTACK_PLAIN = {
  ORIGIN_HIJACK:     'falsely claimed ownership of',
  SUBPREFIX_HIJACK:  'silently captured traffic for',
  ROUTE_LEAK:        'accidentally exposed routes for',
  PATH_MANIPULATION: 'inserted itself into the path for',
}

export default function WhatHappened() {
  const incidents  = useSHYENStore(s => s.incidents)
  const systemTime = useSHYENStore(s => s.systemTime)
  const latest     = incidents[0]

  if (!latest) {
    return (
      <div style={baseStyle}>
        <Label />
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: 'var(--text-muted)',
        }}>
          Monitoring active — no anomalies detected yet.
        </div>
      </div>
    )
  }

  const secAgo = Math.floor(
    (new Date(systemTime) - new Date(latest.timestamp)) / 1000
  )

  const timeStr =
    secAgo < 60
      ? `${secAgo} seconds ago`
      : `${Math.floor(secAgo / 60)} minutes ago`

  const action =
    ATTACK_PLAIN[latest.type] || 'attacked'

  const impact =
    SECTOR_IMPACT[latest.victim.sector] ||
    'critical infrastructure may be affected'

  const COUNTRY_NAMES = {
    CN: 'China',
    PK: 'Pakistan',
    US: 'USA',
    DE: 'Germany',
    IT: 'Italy',
    AU: 'Australia',
    JP: 'Japan',
    EG: 'Egypt',
    RU: 'Russia',
    GB: 'United Kingdom',
    NL: 'Netherlands',
    FR: 'France',
    BR: 'Brazil',
    SG: 'Singapore',
    KR: 'South Korea',
    CA: 'Canada',
    TR: 'Turkey',
    IR: 'Iran',
    SA: 'Saudi Arabia',
    AE: 'UAE',
  }

  const countryName =
    COUNTRY_NAMES[latest.attacker.country] ??
    latest.attacker.country

  const country =
    latest.attacker.country &&
    latest.attacker.country !== '??'
      ? `a network in ${countryName}`
      : 'an unidentified network'

  const mitigated = latest.status === 'MITIGATED'
  const isReal =
    latest.isRealData && !latest.isSimulated

  const cmReady = latest.countermeasuresReady

  return (
    <div style={baseStyle}>
      <Label />

      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--text-primary)',
        lineHeight: 1.7,
      }}>
        <span style={{ color: 'var(--text-muted)' }}>
          {timeStr}:{' '}
        </span>

        {country}{' '}

        <span style={{ color: '#ff6b00' }}>
          {action}
        </span>{' '}

        <span style={{
          color: '#fff',
          fontWeight: 700,
        }}>
          {latest.victim.name}
        </span>

        {' '}— {impact}.{' '}

        {isReal
          ? cmReady
            ? (
              <span style={{
                color: '#ffd60a',
                fontWeight: 700,
              }}>
                HexaSentinel generated real RPKI/RTBH/Flowspec
                countermeasures — pending NOC authorization.
              </span>
            )
            : (
              <span style={{ color: '#ffd60a' }}>
                HexaSentinel detected it in under 90 seconds.
                Generating countermeasures…
              </span>
            )
          : mitigated
            ? (
              <span style={{
                color: '#30d158',
                fontWeight: 700,
              }}>
                [DEMO] Simulated mitigation complete.
              </span>
            )
            : (
              <span style={{ color: '#ffd60a' }}>
                [DEMO] HexaSentinel detected it in under 90 seconds.
                Response in progress.
              </span>
            )}
      </div>
    </div>
  )
}

function Label() {
  return (
    <div style={{
      fontFamily: 'var(--font-mono)',
      fontSize: 8,
      color: 'var(--accent-blue)',
      letterSpacing: '0.15em',
      marginBottom: 4,
    }}>
      ◈ WHAT JUST HAPPENED
    </div>
  )
}

const baseStyle = {
  padding: '8px 20px',
  borderBottom: '1px solid var(--border-subtle)',
  background: 'rgba(0,191,255,0.03)',
  flexShrink: 0,
}
