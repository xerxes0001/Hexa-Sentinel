import { useState, useEffect, useRef } from 'react'
import { analyzeIncidentLocal } from '../../api/hexasentinelAPI.js'

export default function AIAnalysis({ incident, compact }) {
  const cacheRef = useRef({})
  const reqRef   = useRef(0)

  const cached = incident ? cacheRef.current[incident.id] : null

  const [text,    setText]    = useState(cached ?? null)
  const [loading, setLoading] = useState(false)
  const [source,  setSource]  = useState(cached ? 'ai' : null)

  useEffect(() => {
    if (!incident) return

    // Already AI-cached — show immediately
    if (cacheRef.current[incident.id]) {
      setText(cacheRef.current[incident.id])
      setSource('ai')
      setLoading(false)
      return
    }

    // Demo Mode incidents can carry pre-scripted analysis text.
    // This keeps the demo fully functional without requiring the
    // local HexaSentinel backend to be running.
    if (incident.demoAnalysisText) {
      cacheRef.current[incident.id] = incident.demoAnalysisText
      setText(incident.demoAnalysisText)
      setSource('ai')
      setLoading(false)
      return
    }

    // Read deterministicSummary inside the effect so it is always
    // fresh for the current incident.
    const deterministicText = incident.deterministicSummary ?? null

    // Show deterministic assessment immediately while AI loads.
    if (deterministicText) {
      setText(deterministicText)
      setSource('deterministic')
    } else {
      setText(null)
      setSource(null)
    }

    const myToken = ++reqRef.current
    setLoading(true)

    const controller = new AbortController()
    let settled = false

    // Do not leave the UI waiting indefinitely for the local AI server.
    const timer = setTimeout(() => {
      if (settled || reqRef.current !== myToken) return

      settled = true

      // Keep the deterministic assessment visible if the
      // HexaSentinel backend does not respond in time.
      setLoading(false)

      if (deterministicText) {
        setSource('deterministic')
      }
    }, 25000)

    analyzeIncidentLocal(incident, controller.signal)
      .then(result => {
        clearTimeout(timer)

        if (settled || reqRef.current !== myToken) return

        settled = true

        const isBackendUnavailable =
          !result ||
          result.includes?.('HexaSentinel backend unavailable') ||
          result.includes?.('HexaSentinel backend not running')

        if (!isBackendUnavailable) {
          cacheRef.current[incident.id] = result
          setText(result)
          setSource('ai')
        }

        // If AI is unavailable, keep the deterministic assessment.
        setLoading(false)
      })
      .catch(err => {
        clearTimeout(timer)

        if (settled || reqRef.current !== myToken) return

        settled = true

        if (err.name !== 'AbortError') {
          setLoading(false)
        }

        // Deterministic assessment remains visible.
      })

    return () => {
      clearTimeout(timer)
      controller.abort()
      reqRef.current++
    }
  }, [incident?.id])

  const displayText = text ?? 'Compiling threat assessment...'

  const sourceLabel =
    source === 'ai'
      ? '▸ AI ANALYSIS · Llama 3.2 3B — Hexagon NPU'
      : source === 'deterministic'
      ? '▸ AUTONOMOUS ASSESSMENT · HexaSentinel + Llama 3.2 3B'
      : '▸ ANALYZING...'

  const sourceColor =
    source === 'ai'
      ? 'var(--accent-blue)'
      : source === 'deterministic'
      ? 'var(--accent-green)'
      : 'var(--text-muted)'

  // ─────────────────────────────────────────────────────────────────────────
  // COMPACT MODE
  // ─────────────────────────────────────────────────────────────────────────

  if (compact) {
    return (
      <div
        style={{
          padding: '8px 10px',
          background: 'rgba(0,191,255,0.04)',
          border: '1px solid rgba(0,191,255,0.15)',
          borderRadius: 3,
          minHeight: 36,
        }}
      >
        {loading && source === null ? (
          <div
            style={{
              display: 'flex',
              gap: 5,
              alignItems: 'center',
              padding: '4px 0',
            }}
          >
            {[0, 0.16, 0.32, 0.48, 0.64].map((d, i) => (
              <div
                key={i}
                style={{
                  width: 5,
                  height: 5,
                  background: 'var(--accent-blue)',
                  borderRadius: '50%',
                  animation: `dotBounce 1.4s ease-in-out ${d}s infinite`,
                }}
              />
            ))}

            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 8,
                color: 'var(--text-muted)',
                marginLeft: 6,
              }}
            >
              Analyzing incident...
            </span>
          </div>
        ) : (
          <>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 7,
                color: sourceColor,
                letterSpacing: '0.1em',
                marginBottom: 4,
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              {sourceLabel}

              {loading && (
                <span style={{ opacity: 0.5 }}>
                  · upgrading to AI...
                </span>
              )}
            </div>

            <pre
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                color: '#99d6ff',
                lineHeight: 1.7,
                whiteSpace: 'pre-wrap',
                margin: 0,
                wordBreak: 'break-word',
              }}
            >
              {displayText}
            </pre>
          </>
        )}
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────
  // FULL MODE
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div
      style={{
        marginBottom: 16,
        background: 'rgba(0,191,255,0.04)',
        border: '1px solid rgba(0,191,255,0.15)',
        borderRadius: 4,
        padding: 16,
        minHeight: 60,
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: sourceColor,
          letterSpacing: 2,
          marginBottom: 10,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        {sourceLabel}

        {loading && (
          <span style={{ opacity: 0.5 }}>
            · fetching AI upgrade...
          </span>
        )}
      </div>

      <pre
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: '#99d6ff',
          lineHeight: 1.8,
          whiteSpace: 'pre-wrap',
          margin: 0,
          wordBreak: 'break-word',
        }}
      >
        {displayText}
      </pre>
    </div>
  )
}
