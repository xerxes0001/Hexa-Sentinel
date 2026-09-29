/**
 * Threat Impact Tree
 * ─────────────────────────────────────────────────────────────────────────────
 * Endpoint-security visualization for HexaSentinel.
 *
 * This component intentionally keeps the same `tree` input shape used by the
 * existing Threat Impact / Blast Radius engine so it can be dropped in without
 * changing the surrounding panel.
 *
 * Recommended terminology for HexaSentinel:
 *
 *   hijacker -> threat / malicious process
 *   victim   -> affected endpoint
 *   affected -> exposed component/resource
 *   blocked  -> contained / prevented
 *
 * The component is purely visual. It does NOT claim that a threat actually
 * propagated through the machine unless the supplied tree data says so.
 */

import { useState } from 'react'

const ROLE_COLOR = {
  hijacker: '#ff2d55',
  threat: '#ff2d55',

  victim: '#ffd60a',
  endpoint: '#ffd60a',

  affected: '#bf5af2',
  exposed: '#bf5af2',

  blocked: '#3a4452',
  contained: '#30d158',

  process: '#00bfff',
  file: '#ff9f0a',
  network: '#00ff88',
  service: '#bf5af2',
  unknown: '#8b96a4',
}

const KIND_ICON = {
  threat: '◆',
  malicious_process: '◆',

  process: '●',
  file: '■',
  network: '▲',
  connection: '▲',
  service: '◆',
  endpoint: '⬢',

  tier1: '◆',
  foreign: '●',
  indian: '▲',
  ixp: '■',

  unknown: '○',
}

const ROW_HEIGHT = 82
const NODE_R = 17
const PADDING = 46

function getRoleColor(node) {
  if (!node) return ROLE_COLOR.unknown

  return (
    ROLE_COLOR[node.role] ??
    ROLE_COLOR[node.kind] ??
    ROLE_COLOR.unknown
  )
}

function getNodeIcon(node) {
  if (!node) return KIND_ICON.unknown

  if (node.role === 'blocked' || node.role === 'contained') {
    return node.role === 'contained' ? '✓' : '✕'
  }

  return KIND_ICON[node.kind] ?? KIND_ICON.unknown
}

function getNodeLabel(node) {
  if (!node) return 'Unknown'

  return (
    node.name ??
    node.label ??
    node.asn ??
    node.id ??
    'Unknown'
  )
}

function getNodeIdentifier(node) {
  if (!node) return ''

  return (
    node.id ??
    node.asn ??
    node.pid ??
    node.hash ??
    ''
  )
}

function getNodeDescription(node) {
  if (!node) return ''

  if (node.description) return node.description

  switch (node.kind) {
    case 'process':
    case 'malicious_process':
      return 'Process activity'

    case 'file':
      return 'File activity'

    case 'network':
    case 'connection':
      return 'Network connection'

    case 'service':
      return 'System service'

    case 'endpoint':
      return 'Affected endpoint'

    default:
      return node.role ?? 'Unknown component'
  }
}

function isBlocked(node) {
  return node?.role === 'blocked' || node?.role === 'contained'
}

function truncate(value, length = 16) {
  if (!value) return ''

  const text = String(value)

  return text.length > length
    ? `${text.slice(0, length - 1)}…`
    : text
}

export default function BlastRadiusTree({
  tree,
  width = 640,
}) {
  const [hovered, setHovered] = useState(null)

  if (!tree || !Array.isArray(tree.nodes) || tree.nodes.length === 0) {
    return (
      <div
        style={{
          padding: '24px 12px',
          textAlign: 'center',
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-muted)',
        }}
      >
        No threat impact data available.
      </div>
    )
  }

  /*
   * Build rows from hop/depth.
   *
   * Existing BGP data uses `hop`.
   * Endpoint-security data may use `depth`.
   *
   * Supporting both allows the visualization to survive while the rest of
   * the application is being migrated from SnapShield to HexaSentinel.
   */
  const getDepth = node => {
    if (Number.isFinite(node.hop)) return node.hop
    if (Number.isFinite(node.depth)) return node.depth
    return 0
  }

  const maxDepth = Math.max(
    ...tree.nodes.map(getDepth)
  )

  const rows = []

  for (let depth = 0; depth <= maxDepth; depth++) {
    rows.push(
      tree.nodes.filter(
        node => getDepth(node) === depth
      )
    )
  }

  const height =
    PADDING * 2 +
    maxDepth * ROW_HEIGHT +
    NODE_R * 2 +
    30

  /*
   * Calculate deterministic positions.
   */
  const pos = new Map()

  rows.forEach((row, depth) => {
    const y =
      PADDING +
      depth * ROW_HEIGHT +
      NODE_R

    const usableWidth =
      width - PADDING * 2

    row.forEach((node, index) => {
      const x =
        row.length === 1
          ? width / 2
          : PADDING +
            (usableWidth * (index + 0.5)) /
              row.length

      const id =
        node.asn ??
        node.id ??
        node.pid ??
        node.hash ??
        node.name

      pos.set(id, {
        x,
        y,
      })
    })
  })

  const nodeById = new Map()

  tree.nodes.forEach(node => {
    const id =
      node.asn ??
      node.id ??
      node.pid ??
      node.hash ??
      node.name

    nodeById.set(id, node)
  })

  function getNodeId(node) {
    return (
      node?.asn ??
      node?.id ??
      node?.pid ??
      node?.hash ??
      node?.name
    )
  }

  function getEdgeId(value) {
    if (!value) return null

    if (typeof value === 'string') {
      return value
    }

    return getNodeId(value)
  }

  return (
    <div
      style={{
        position: 'relative',
        width: '100%',
        overflowX: 'auto',
      }}
    >
      <svg
        width={width}
        height={height}
        style={{
          display: 'block',
          margin: '0 auto',
        }}
        role="img"
        aria-label="HexaSentinel threat impact graph"
      >

        {/* Background grid */}
        <defs>
          <pattern
            id="hexasentinel-grid"
            width="24"
            height="24"
            patternUnits="userSpaceOnUse"
          >
            <path
              d="M 24 0 L 0 0 0 24"
              fill="none"
              stroke="rgba(255,255,255,0.025)"
              strokeWidth="1"
            />
          </pattern>
        </defs>

        <rect
          width="100%"
          height="100%"
          fill="url(#hexasentinel-grid)"
          opacity="0.35"
        />

        {/* Depth labels */}
        {rows.map((row, depth) => {
          if (row.length === 0) return null

          const y =
            PADDING +
            depth * ROW_HEIGHT +
            NODE_R

          return (
            <text
              key={`depth-${depth}`}
              x={8}
              y={y + 3}
              fontSize={7}
              fill="#5c6773"
              fontFamily="var(--font-mono)"
            >
              {depth === 0
                ? 'THREAT'
                : `IMPACT ${depth}`}
            </text>
          )
        })}

        {/* Edges */}
        {Array.isArray(tree.edges) &&
          tree.edges.map((edge, index) => {
            const fromId = getEdgeId(edge.from)
            const toId = getEdgeId(edge.to)

            const from = pos.get(fromId)
            const to = pos.get(toId)

            if (!from || !to) {
              return null
            }

            const targetNode =
              nodeById.get(toId)

            const blocked =
              isBlocked(targetNode)

            const color =
              blocked
                ? '#3a4452'
                : 'rgba(191,90,242,0.42)'

            return (
              <g key={`edge-${index}`}>
                <line
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke={color}
                  strokeWidth={
                    blocked ? 1 : 1.6
                  }
                  strokeDasharray={
                    blocked
                      ? '5,4'
                      : undefined
                  }
                />

                {!blocked && (
                  <circle
                    cx={
                      from.x +
                      (to.x - from.x) * 0.5
                    }
                    cy={
                      from.y +
                      (to.y - from.y) * 0.5
                    }
                    r={2}
                    fill="#bf5af2"
                    opacity={0.55}
                  />
                )}
              </g>
            )
          })}

        {/* Nodes */}
        {tree.nodes.map(node => {
          const id = getNodeId(node)
          const p = pos.get(id)

          if (!p) return null

          const color =
            getRoleColor(node)

          const blocked =
            isBlocked(node)

          const isHovered =
            hovered === id

          const label =
            getNodeLabel(node)

          return (
            <g
              key={id}
              transform={`translate(${p.x},${p.y})`}
              onMouseEnter={() =>
                setHovered(id)
              }
              onMouseLeave={() =>
                setHovered(null)
              }
              style={{
                cursor: 'pointer',
              }}
            >
              {/* Threat glow */}
              {!blocked &&
                (node.role === 'hijacker' ||
                  node.role === 'threat') && (
                  <circle
                    r={NODE_R + 7}
                    fill="none"
                    stroke="#ff2d55"
                    strokeWidth={1}
                    opacity={0.18}
                  />
                )}

              {/* Node */}
              <circle
                r={
                  isHovered
                    ? NODE_R + 3
                    : NODE_R
                }
                fill={
                  blocked
                    ? 'rgba(58,68,82,0.45)'
                    : `${color}18`
                }
                stroke={color}
                strokeWidth={
                  node.role === 'hijacker' ||
                  node.role === 'threat'
                    ? 2.5
                    : 1.5
                }
                style={{
                  transition: 'r 0.15s',
                }}
              />

              {/* Icon */}
              <text
                textAnchor="middle"
                dominantBaseline="central"
                fontSize={11}
                fill={
                  blocked
                    ? '#5c6773'
                    : color
                }
                fontFamily="var(--font-mono)"
              >
                {getNodeIcon(node)}
              </text>

              {/* Name */}
              <text
                x={0}
                y={NODE_R + 13}
                textAnchor="middle"
                fontSize={8}
                fontFamily="var(--font-mono)"
                fill={
                  blocked
                    ? '#5c6773'
                    : 'var(--text-secondary)'
                }
              >
                {truncate(label, 17)}
              </text>

              {/* Secondary identifier */}
              {getNodeIdentifier(node) &&
                getNodeIdentifier(node) !==
                  label && (
                  <text
                    x={0}
                    y={NODE_R + 24}
                    textAnchor="middle"
                    fontSize={6.5}
                    fontFamily="var(--font-mono)"
                    fill="#4d5663"
                  >
                    {truncate(
                      getNodeIdentifier(node),
                      18
                    )}
                  </text>
                )}
            </g>
          )
        })}
      </svg>

      {/* Hover information */}
      {hovered && (
        <div
          style={{
            position: 'absolute',
            top: 6,
            right: 6,
            padding: '9px 11px',
            background:
              'rgba(6,10,16,0.96)',
            border:
              '1px solid var(--border-mid)',
            borderRadius: 4,
            fontFamily:
              'var(--font-mono)',
            fontSize: 9,
            color:
              'var(--text-primary)',
            maxWidth: 230,
            pointerEvents: 'none',
            boxShadow:
              '0 8px 30px rgba(0,0,0,0.45)',
          }}
        >
          {(() => {
            const node =
              nodeById.get(hovered)

            if (!node) return null

            const color =
              getRoleColor(node)

            const depth =
              getDepth(node)

            return (
              <>
                <div
                  style={{
                    fontWeight: 700,
                    color,
                    marginBottom: 4,
                  }}
                >
                  {getNodeLabel(node)}
                </div>

                {getNodeIdentifier(node) && (
                  <div
                    style={{
                      color:
                        'var(--text-muted)',
                      marginBottom: 3,
                    }}
                  >
                    {getNodeIdentifier(node)}
                  </div>
                )}

                <div
                  style={{
                    color:
                      'var(--text-muted)',
                    marginBottom: 3,
                  }}
                >
                  {getNodeDescription(node)}
                </div>

                <div
                  style={{
                    color:
                      'var(--text-muted)',
                    marginTop: 4,
                  }}
                >
                  {node.role === 'blocked'
                    ? 'Contained by security controls'
                    : node.role ===
                        'contained'
                      ? 'Threat contained'
                      : `Impact depth ${depth}`}
                </div>
              </>
            )
          })()}
        </div>
      )}

      {/* Legend */}
      <div
        style={{
          display: 'flex',
          gap: 14,
          flexWrap: 'wrap',
          justifyContent:
            'center',
          marginTop: 8,
          fontFamily:
            'var(--font-mono)',
          fontSize: 7.5,
          color:
            'var(--text-muted)',
        }}
      >
        <span>
          <span
            style={{
              color: '#ff2d55',
            }}
          >
            ●
          </span>{' '}
          Threat
        </span>

        <span>
          <span
            style={{
              color: '#ffd60a',
            }}
          >
            ●
          </span>{' '}
          Endpoint
        </span>

        <span>
          <span
            style={{
              color: '#bf5af2',
            }}
          >
            ●
          </span>{' '}
          Exposed
        </span>

        <span>
          <span
            style={{
              color: '#30d158',
            }}
          >
            ✓
          </span>{' '}
          Contained
        </span>

        <span>
          <span
            style={{
              color: '#5c6773',
            }}
          >
            ✕
          </span>{' '}
          Blocked
        </span>

        <span>
          ◆ Process&nbsp;&nbsp; ■ File&nbsp;&nbsp;
          ▲ Network&nbsp;&nbsp; ● Resource
        </span>
      </div>
    </div>
  )
}
