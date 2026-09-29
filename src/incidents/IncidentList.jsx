import { useState } from 'react'
import { useSHYENStore } from '../../store/useSHYENStore.js'
import IncidentCard from './IncidentCard.jsx'

const FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low']

export default function IncidentList({ filteredIncidents }) {
  const incidents = useSHYENStore(s => s.incidents)
  const selectedId = useSHYENStore(s => s.selectedIncidentId)
  const selectIncident = useSHYENStore(s => s.selectIncident)
  const triggerAction = useSHYENStore(s => s.triggerAction)

  const [filter, setFilter] = useState('All')

  const base = filteredIncidents ?? incidents

  const displayed =
    filter === 'All'
      ? base
      : base.filter(
          incident =>
            incident.severity === filter.toUpperCase()
        )

  const isFiltered =
    filteredIncidents &&
    filteredIncidents.length !== incidents.length

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      {/* Filter tabs */}
      <div
        style={{
          display: 'flex',
          gap: 4,
          padding: '8px 10px',
          borderBottom: '1px solid var(--border-subtle)',
          flexShrink: 0,
        }}
      >
        {FILTERS.map(filterName => {
          const active = filter === filterName

          const colors = {
            Critical: '#ff2d55',
            High: '#ff6b00',
            Medium: '#ffd60a',
            Low: '#30d158',
            All: 'var(--accent-green)',
          }

          return (
            <button
              key={filterName}
              onClick={() => setFilter(filterName)}
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                letterSpacing: '0.05em',
                padding: '3px 10px',
                borderRadius: 3,
                cursor: 'pointer',
                background: active
                  ? colors[filterName]
                  : 'rgba(255,255,255,0.03)',
                border: `1px solid ${
                  active
                    ? colors[filterName]
                    : 'var(--border-subtle)'
                }`,
                color: active ? '#000' : 'var(--text-muted)',
                fontWeight: active ? 700 : 400,
                transition: 'all 0.15s',
              }}
            >
              {filterName}
            </button>
          )
        })}
      </div>

      {/* Active filter indicator */}
      {isFiltered && (
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--accent-red)',
            padding: '4px 10px',
            background: 'rgba(255,45,85,0.05)',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          ◈ FILTERED · {filteredIncidents.length} of {incidents.length}
        </div>
      )}

      {/* Incident list */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '6px 8px',
        }}
      >
        {incidents.length === 0 ? (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              height: 120,
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-muted)',
              textAlign: 'center',
              lineHeight: 2,
            }}
          >
            HexaSentinel is monitoring BGP feeds...
            <br />
            No routing anomalies detected.
          </div>
        ) : displayed.length === 0 ? (
          <div
            style={{
              padding: 20,
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-muted)',
              textAlign: 'center',
            }}
          >
            No {filter.toLowerCase()} incidents.
          </div>
        ) : (
          displayed.map(incident => (
            <IncidentCard
              key={incident.id}
              incident={incident}
              selected={incident.id === selectedId}
              onClick={() => selectIncident(incident.id)}
              onAction={triggerAction}
            />
          ))
        )}
      </div>

      {/* View all button */}
      {incidents.length > 0 && (
        <div
          style={{
            padding: '8px 10px',
            borderTop: '1px solid var(--border-subtle)',
            flexShrink: 0,
          }}
        >
          <button
            onClick={() => setFilter('All')}
            style={{
              width: '100%',
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-muted)',
              background: 'rgba(255,255,255,0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 3,
              padding: '6px 0',
              cursor: 'pointer',
              letterSpacing: '0.08em',
            }}
          >
            ↗ View All Incidents ({incidents.length})
          </button>
        </div>
      )}
    </div>
  )
}
