import { useMemo } from 'react'
import { useSHYENStore } from '../../store/useSHYENStore.js'

const TYPE_COLORS = {
  browser: '#00bfff',
  system: '#bf5af2',
  shell: '#ff6b00',
  security: '#00ff88',
  unknown: '#8b96a4',
}

const TYPE_ICONS = {
  browser: '◉',
  system: '◆',
  shell: '>',
  security: '◈',
  unknown: '○',
}

function classifyProcess(name = '') {
  const value = name.toLowerCase()

  if (
    value.includes('chrome') ||
    value.includes('firefox') ||
    value.includes('edge') ||
    value.includes('safari')
  ) {
    return 'browser'
  }

  if (
    value.includes('powershell') ||
    value.includes('cmd') ||
    value.includes('bash') ||
    value.includes('terminal')
  ) {
    return 'shell'
  }

  if (
    value.includes('defender') ||
    value.includes('security') ||
    value.includes('sentinel')
  ) {
    return 'security'
  }

  if (
    value.includes('system') ||
    value.includes('svchost') ||
    value.includes('launchd')
  ) {
    return 'system'
  }

  return 'unknown'
}

function ProcessCard({ process }) {
  const type = classifyProcess(process.name)
  const color = TYPE_COLORS[type]

  const suspicious = !!process.suspicious

  return (
    <div
      style={{
        minWidth: 165,
        padding: '10px 12px',
        background: 'rgba(10,18,28,0.8)',
        border: `1px solid ${
          suspicious
            ? 'rgba(255,45,85,0.35)'
            : 'var(--border-subtle)'
        }`,
        borderTop: suspicious
          ? '2px solid #ff2d55'
          : '2px solid transparent',
        borderRadius: 4,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          marginBottom: 8,
        }}
      >
        <div
          style={{
            width: 27,
            height: 27,
            borderRadius: '50%',
            background: `${color}18`,
            border: `1px solid ${color}44`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color,
            fontSize: 12,
          }}
        >
          {TYPE_ICONS[type]}
        </div>

        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 7,
              color: 'var(--text-muted)',
            }}
          >
            PID {process.pid ?? '—'}
          </div>

          <div
            style={{
              fontFamily: 'var(--font-display)',
              fontSize: 10,
              fontWeight: 700,
              color: 'var(--text-primary)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              maxWidth: 110,
            }}
          >
            {process.name ?? 'Unknown'}
          </div>
        </div>
      </div>

      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: suspicious
            ? '#ff2d55'
            : '#30d158',
        }}
      >
        {suspicious ? 'SUSPICIOUS' : 'MONITORED'}
      </div>

      <div
        style={{
          marginTop: 5,
          fontFamily: 'var(--font-mono)',
          fontSize: 7,
          color: 'var(--text-muted)',
        }}
      >
        {process.path ?? 'Path unavailable'}
      </div>
    </div>
  )
}

export default function EndpointHealthGrid() {
  const processes = useSHYENStore(
    s => s.processes ?? []
  )

  const incidents = useSHYENStore(
    s => s.incidents ?? []
  )

  const fallbackProcesses = useMemo(() => {
    if (processes.length > 0) return processes

    return incidents
      .flatMap(i => i.processes ?? [])
      .slice(0, 20)
  }, [processes, incidents])

  const suspiciousCount = fallbackProcesses.filter(
    p => p.suspicious
  ).length

  return (
    <div style={{ padding: '12px 10px' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          marginBottom: 2,
        }}
      >
        <div
          style={{
            fontFamily: 'var(--font-display)',
            fontSize: 12,
            fontWeight: 700,
          }}
        >
          ENDPOINT HEALTH
        </div>

        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: suspiciousCount > 0
              ? '#ff2d55'
              : '#30d158',
          }}
        >
          {suspiciousCount} SUSPICIOUS
        </div>
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
        Local process security status
      </div>

      {fallbackProcesses.length === 0 ? (
        <div
          style={{
            padding: 20,
            textAlign: 'center',
            border: '1px solid var(--border-subtle)',
            borderRadius: 4,
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
          }}
        >
          WAITING FOR ENDPOINT TELEMETRY...
        </div>
      ) : (
        <div
          style={{
            display: 'flex',
            gap: 8,
            overflowX: 'auto',
            paddingBottom: 6,
          }}
        >
          {fallbackProcesses.map((process, index) => (
            <ProcessCard
              key={
                process.pid ??
                `${process.name}-${index}`
              }
              process={process}
            />
          ))}
        </div>
      )}
    </div>
  )
}
