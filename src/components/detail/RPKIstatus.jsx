import { useState, useEffect } from 'react'
import { checkRPKI } from '../../api/rpkiCheck.js'

export default function RPKIStatus({ asn, prefix, presetStatus }) {
  const [status, setStatus] = useState(presetStatus ?? null)
  const [loading, setLoading] = useState(!presetStatus)
  const [retries, setRetries] = useState(0)

  useEffect(() => {
    // Demo Mode incidents carry pre-scripted RPKI status so HexaSentinel
    // can show a complete, realistic result without making a live network
    // call. Live incidents use the RPKI API check instead.
    if (presetStatus) {
      setStatus(presetStatus)
      setLoading(false)
      return
    }

    if (!asn || !prefix) {
      setLoading(false)
      return
    }

    setLoading(true)
    setStatus(null)

    checkRPKI(asn, prefix)
      .then(result => {
        setStatus(result)
        setLoading(false)
      })
      .catch(() => {
        setStatus(null)
        setLoading(false)
      })
  }, [asn, prefix, retries, presetStatus])

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '8px 10px',
          background: 'rgba(255,255,255,0.02)',
          borderRadius: 4,
          marginBottom: 8,
        }}
      >
        <div
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#444',
            animation: 'termBlink 1s ease infinite',
          }}
        />

        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--text-muted)',
          }}
        >
          Checking RPKI via Cloudflare...
        </span>
      </div>
    )
  }

  if (!status) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 10px',
          background: 'rgba(255,255,255,0.02)',
          borderRadius: 4,
          marginBottom: 8,
        }}
      >
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--text-muted)',
          }}
        >
          RPKI check unavailable — {prefix ?? 'no prefix'}
        </span>

        <button
          onClick={() => setRetries(r => r + 1)}
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--accent-blue)',
            background: 'none',
            border: '1px solid rgba(0,191,255,0.3)',
            borderRadius: 2,
            padding: '2px 8px',
            cursor: 'pointer',
          }}
        >
          RETRY
        </button>
      </div>
    )
  }

  const color = status.valid
    ? '#30d158'
    : status.invalid
      ? '#ff2d55'
      : '#ffd60a'

  const label = status.valid
    ? '✓ RPKI VALID'
    : status.invalid
      ? '✗ RPKI INVALID'
      : '? RPKI UNKNOWN'

  const message = status.valid
    ? 'Valid ROA exists. ROV-compliant routers will reject hijack attempts.'
    : status.invalid
      ? 'INVALID — no route origin authorization. Highly vulnerable to hijacking.'
      : 'No RPKI record found. Recommend immediate ROA creation via IRINN.'

  return (
    <div
      style={{
        padding: '8px 12px',
        borderRadius: 4,
        marginBottom: 8,
        background: `${color}0a`,
        border: `1px solid ${color}33`,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 4,
        }}
      >
        <div
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: color,
            boxShadow: `0 0 4px ${color}`,
          }}
        />

        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color,
            fontWeight: 700,
            letterSpacing: '0.1em',
          }}
        >
          {label}
        </span>

        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-muted)',
            marginLeft: 'auto',
          }}
        >
          Cloudflare RPKI
        </span>
      </div>

      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
        }}
      >
        {message}
      </div>

      {!status.valid && (
        <div
          style={{
            marginTop: 6,
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: '#ff2d55',
            fontWeight: 700,
          }}
        >
          ⚠ THIS PREFIX IS UNPROTECTED
        </div>
      )}
    </div>
  )
}
