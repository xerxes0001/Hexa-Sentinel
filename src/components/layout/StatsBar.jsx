import { useSHYENStore } from '../../store/useSHYENStore.js'
import { INDIAN_ASNS } from '../../data/indianASNs.js'

function StatCard({ label, value, color, sub, delta, deltaColor }) {
  return (
    <div
      style={{
        flex: 1,
        padding: '12px 20px',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: 'var(--text-muted)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>

      <div
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: 28,
          fontWeight: 800,
          color,
          lineHeight: 1,
        }}
      >
        {value}
      </div>

      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: deltaColor ?? 'var(--text-muted)',
        }}
      >
        {delta && (
          <span
            style={{
              color: deltaColor ?? 'var(--accent-green)',
            }}
          >
            {delta}{' '}
          </span>
        )}
        {sub}
      </div>
    </div>
  )
}

export default function StatsBar() {
  const totalAnnouncements = useSHYENStore(
    s => s.totalAnnouncements
  )

  const incidents = useSHYENStore(
    s => s.incidents
  )

  const risIndianCount = useSHYENStore(
    s => s.risIndianCount
  )

  const apnicCount = useSHYENStore(
    s => s.apnicCount
  )

  const systemTime = useSHYENStore(
    s => s.systemTime
  )

  const active = incidents.filter(
    i => i.status === 'DETECTED'
  ).length

  // HexaSentinel generates countermeasure artifacts for
  // incidents but does not directly deploy them to the network.
  const cmReady = incidents.filter(
    i => i.countermeasuresReady
  ).length

  // Simulated incidents may be marked as mitigated inside
  // the demo environment. Real incidents require operator
  // authorization before any network mitigation is performed.
  const demoMit = incidents.filter(
    i => i.isSimulated && i.status === 'MITIGATED'
  ).length

  const avgConf =
    incidents.length > 0
      ? Math.round(
          incidents.reduce(
            (s, i) => s + (i.confidence ?? 0),
            0
          ) / incidents.length
        )
      : 0

  const timeStr =
    new Date(systemTime)
      .toISOString()
      .replace('T', ' ')
      .slice(0, 19) + ' UTC'

  return (
    <div
      style={{
        display: 'flex',
        height: 72,
        borderBottom: '1px solid var(--border-subtle)',
        background: '#07111a',
        flexShrink: 0,
      }}
    >
      <StatCard
        label="Active Incidents"
        value={active}
        color="var(--accent-red)"
        delta="↑ live"
        deltaColor="var(--accent-red)"
        sub="from RIPE RIS feed"
      />

      <StatCard
        label="Countermeasures Ready"
        value={cmReady}
        color="#30d158"
        delta={
          cmReady > 0
            ? `↑ ${cmReady}`
            : ''
        }
        deltaColor="#30d158"
        sub={
          demoMit > 0
            ? `+ ${demoMit} demo`
            : 'pending NOC authorization'
        }
      />

      <StatCard
        label="Indian ASNs Monitored"
        value={INDIAN_ASNS.length}
        color="var(--accent-blue)"
        sub="All critical networks"
      />

      <StatCard
        label="Threat Confidence"
        value={
          avgConf > 0
            ? `${avgConf}%`
            : '—'
        }
        color="var(--accent-purple)"
        sub="Average confidence"
      />

      <StatCard
        label="Vantage Points"
        value={8}
        color="var(--accent-amber)"
        sub="Global monitoring"
      />
    </div>
  )
}
