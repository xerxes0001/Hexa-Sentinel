import { useState, useEffect } from 'react'
import { useSHYENStore } from '../../store/useSHYENStore.js'
import { queryHexaSentinel } from '../../api/hexasentinelAPI.js'

const SYSTEM_PROMPT = `You are HexaSentinel, an on-device network security analyst powered by Llama 3.2 3B on the Qualcomm Hexagon NPU. Answer questions about BGP incidents, network threats, routing security, RPKI, and Indian internet infrastructure concisely and technically. Keep answers under 100 words. No markdown formatting.`

async function queryAI(question, context) {
  try {
    const result = await queryHexaSentinel(
      SYSTEM_PROMPT,
      `Current incidents:\n${context}\n\nQuestion: ${question}`,
      200,
      0.3,
    )

    return result ?? 'No response from HexaSentinel AI. Please try again in a moment.'
  } catch (e) {
    return `Query error: ${e.message}`
  }
}

export default function ConversationalQuery({ compact, incidentId }) {
  const incidents = useSHYENStore(s => s.incidents)

  const [query, setQuery] = useState('')
  const [answer, setAnswer] = useState('')
  const [loading, setLoading] = useState(false)
  const [open, setOpen] = useState(false)

  // Reset Q&A when selected incident changes.
  useEffect(() => {
    setQuery('')
    setAnswer('')
    setLoading(false)
  }, [incidentId])

  const SUGGESTIONS = [
    'Which sector is most targeted?',
    'Summarize all CRITICAL incidents',
    'Which attacker is most active?',
    'What happened in the last hour?',
  ]

  async function ask(q) {
    const question = q.trim()

    if (!question || loading) return

    setLoading(true)
    setAnswer('')
    setOpen(true)

    const context = (incidents ?? [])
      .slice(0, 10)
      .map(i =>
        `[${i.severity}] ${i.type} on ${i.victim?.name} (${i.victim?.sector}) from ${i.attacker?.asn} [${i.attacker?.country}] - status: ${i.status}`
      )
      .join('\n')

    const result = await queryAI(question, context)

    setAnswer(result)
    setLoading(false)
  }

  if (compact) {
    return (
      <div style={{ marginTop: 8 }}>

        <button
          onClick={() => setOpen(!open)}
          style={{
            width: '100%',
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            fontWeight: 700,
            color: '#fff',
            letterSpacing: '0.1em',
            background: 'linear-gradient(135deg, #6b46c1, #553c9a)',
            border: 'none',
            borderRadius: 4,
            padding: '10px 0',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
          }}
        >
          ✦ Ask HexaSentinel AI
        </button>

        {open && (
          <div style={{ marginTop: 8 }}>

            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 4,
                marginBottom: 6,
              }}
            >
              {SUGGESTIONS.map(suggestion => (
                <button
                  key={suggestion}
                  onClick={() => {
                    setQuery(suggestion)
                    ask(suggestion)
                  }}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 8,
                    color: 'var(--text-muted)',
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 3,
                    padding: '3px 7px',
                    cursor: 'pointer',
                  }}
                >
                  {suggestion}
                </button>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 6 }}>

              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    ask(query)
                  }
                }}
                placeholder="Ask HexaSentinel..."
                disabled={loading}
                style={{
                  flex: 1,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 9,
                  background: 'rgba(6,10,16,0.9)',
                  border: '1px solid var(--border-mid)',
                  color: 'var(--text-primary)',
                  borderRadius: 3,
                  padding: '5px 8px',
                  outline: 'none',
                }}
              />

              <button
                onClick={() => ask(query)}
                disabled={loading || !query.trim()}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 9,
                  fontWeight: 700,
                  color: '#000',
                  background: loading
                    ? '#333'
                    : 'var(--accent-green)',
                  border: 'none',
                  borderRadius: 3,
                  padding: '0 10px',
                  cursor: loading ? 'wait' : 'pointer',
                }}
              >
                {loading ? '...' : 'ASK'}
              </button>

            </div>

            {answer && (
              <pre
                style={{
                  marginTop: 6,
                  padding: '6px 8px',
                  background: 'rgba(0,255,136,0.04)',
                  border: '1px solid rgba(0,255,136,0.12)',
                  borderRadius: 3,
                  fontFamily: 'var(--font-mono)',
                  fontSize: 9,
                  color: '#99ffcc',
                  lineHeight: 1.7,
                  whiteSpace: 'pre-wrap',
                }}
              >
                {answer}
              </pre>
            )}

          </div>
        )}

      </div>
    )
  }

  return (
    <div
      style={{
        marginTop: 16,
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 4,
        padding: 12,
      }}
    >

      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--accent-green)',
          letterSpacing: '0.15em',
          marginBottom: 10,
        }}
      >
        ◈ ASK HEXASENTINEL AI
      </div>

      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 4,
          marginBottom: 8,
        }}
      >
        {SUGGESTIONS.map(suggestion => (
          <button
            key={suggestion}
            onClick={() => {
              setQuery(suggestion)
              ask(suggestion)
            }}
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 8,
              color: 'var(--text-muted)',
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 3,
              padding: '3px 8px',
              cursor: 'pointer',
            }}
          >
            {suggestion}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 6 }}>

        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter') {
              ask(query)
            }
          }}
          placeholder="Ask anything about current incidents..."
          disabled={loading}
          style={{
            flex: 1,
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            background: 'rgba(6,10,16,0.9)',
            border: '1px solid var(--border-mid)',
            color: 'var(--text-primary)',
            borderRadius: 3,
            padding: '6px 10px',
            outline: 'none',
          }}
        />

        <button
          onClick={() => ask(query)}
          disabled={loading || !query.trim()}
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            fontWeight: 700,
            color: '#000',
            background: loading
              ? '#333'
              : 'var(--accent-green)',
            border: 'none',
            borderRadius: 3,
            padding: '0 12px',
            cursor: loading ? 'wait' : 'pointer',
          }}
        >
          {loading ? '...' : 'ASK'}
        </button>

      </div>

      {answer && (
        <pre
          style={{
            marginTop: 10,
            padding: '8px 10px',
            background: 'rgba(0,255,136,0.04)',
            border: '1px solid rgba(0,255,136,0.12)',
            borderRadius: 3,
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: '#99ffcc',
            lineHeight: 1.7,
            whiteSpace: 'pre-wrap',
          }}
        >
          {answer}
        </pre>
      )}

    </div>
  )
}
