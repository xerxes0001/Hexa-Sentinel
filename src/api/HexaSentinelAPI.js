/**
 * hexasentinelAPI.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Hexa Sentinel — Local AI / Backend API
 *
 * Drop-in replacement for:
 *   groqAPI.js
 *   groqActions.js
 *   autonomousAI.js
 *   supabaseClient.js        → removed
 *   backendSync.js            → removed
 *
 * All AI requests go to the local Hexa Sentinel FastAPI server.
 *
 * Default backend:
 *   http://127.0.0.1:8000
 *
 * AI:
 *   Llama 3.2 3B Instruct
 *   Qualcomm AI Hub / Hexagon NPU
 *
 * No cloud AI API keys are required at runtime.
 */

const BASE =
  import.meta.env.VITE_HEXASENTINEL_API_URL ??
  'http://127.0.0.1:8000'


const OFFLINE_MSG =
  'Hexa Sentinel backend unavailable. Start the Python server:\n' +
  '  uvicorn backend.api.main:app --host 127.0.0.1 --port 8000'


// ─────────────────────────────────────────────────────────────────────────────
// Generic POST helper
// ─────────────────────────────────────────────────────────────────────────────

async function post(path, body, signal) {
  const response = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
    signal,
  })

  if (!response.ok) {
    throw new Error(
      `HTTP ${response.status} from ${path}`
    )
  }

  return response.json()
}


// ─────────────────────────────────────────────────────────────────────────────
// 1. analyzeIncidentLocal
// ─────────────────────────────────────────────────────────────────────────────
//
// Replacement for analyzeIncident() in groqAPI.js
//
// Used by:
//   src/components/detail/AIAnalysis.jsx
// ─────────────────────────────────────────────────────────────────────────────

export async function analyzeIncidentLocal(incident, signal) {
  try {
    const data = await post(
      '/api/analyze',
      {
        context: incident,
      },
      signal
    )

    return data?.analysis ?? 'Analysis unavailable.'

  } catch (error) {

    if (error?.name === 'AbortError') {
      throw error
    }

    console.warn(
      '[Hexa Sentinel] analyzeIncidentLocal failed:',
      error?.message
    )

    return OFFLINE_MSG
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 2. chatWithHexaSentinel
// ─────────────────────────────────────────────────────────────────────────────
//
// Replacement for chatWithGroq()
//
// Used by:
//   src/components/chat/AdminChat.jsx
// ─────────────────────────────────────────────────────────────────────────────

export async function chatWithHexaSentinel(
  messages,
  systemContext,
  _unused,
  signal
) {
  try {
    const data = await post(
      '/api/chat',
      {
        messages,
        context: systemContext,
      },
      signal
    )

    return data?.reply ?? 'No response.'

  } catch (error) {

    if (error?.name === 'AbortError') {
      throw error
    }

    console.warn(
      '[Hexa Sentinel] chatWithHexaSentinel failed:',
      error?.message
    )

    return OFFLINE_MSG
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Backward-compatible alias
// ─────────────────────────────────────────────────────────────────────────────
//
// If an existing component still imports chatWithSnapShield,
// this prevents the application from breaking immediately.
//
// New code should use chatWithHexaSentinel.
// ─────────────────────────────────────────────────────────────────────────────

export const chatWithSnapShield = chatWithHexaSentinel


// ─────────────────────────────────────────────────────────────────────────────
// 3. queryHexaSentinel
// ─────────────────────────────────────────────────────────────────────────────
//
// Replacement for callTextAI() in autonomousAI.js
//
// Used by:
//   src/components/detail/ConversationalQuery.jsx
// ─────────────────────────────────────────────────────────────────────────────

export async function queryHexaSentinel(
  systemPrompt,
  userContent,
  _maxTokens,
  _temperature
) {
  try {
    const data = await post('/api/chat', {
      messages: [
        {
          role: 'user',
          content: userContent,
        },
      ],

      context: systemPrompt,
    })

    return data?.reply ?? null

  } catch (error) {

    console.warn(
      '[Hexa Sentinel] queryHexaSentinel failed:',
      error?.message
    )

    return null
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Backward-compatible alias
// ─────────────────────────────────────────────────────────────────────────────

export const querySnapShield = queryHexaSentinel


// ─────────────────────────────────────────────────────────────────────────────
// 4. getDecision
// ─────────────────────────────────────────────────────────────────────────────
//
// Replacement for autonomousDecision() in autonomousAI.js
//
// Used by:
//   src/App.jsx
//
// Sends structured BGP incident information to the local AI.
// ─────────────────────────────────────────────────────────────────────────────

export async function getDecision(incident, _onAnalyzing) {
  try {

    const bgpContext = {
      type: 'bgp_incident',

      // ── Prefix ───────────────────────────────────────
      prefix:
        incident?.prefix ??
        'unknown',

      // ── Attacker ─────────────────────────────────────
      attacker_asn:
        incident?.attacker?.asn ??
        'unknown',

      attacker_name:
        incident?.attacker?.name ??
        'unknown',

      attacker_country:
        incident?.attacker?.country ??
        '??',

      // ── Victim ───────────────────────────────────────
      victim_asn:
        incident?.victim?.asn ??
        'unknown',

      victim_name:
        incident?.victim?.name ??
        'unknown',

      victim_sector:
        incident?.victim?.sector ??
        'unknown',

      // ── Detection information ────────────────────────
      severity:
        incident?.severity ??
        'MEDIUM',

      path_anomaly:
        incident?.pathAnomaly ??
        'none',

      confidence:
        incident?.confidence ??
        50,

      // ── Repeated activity ────────────────────────────
      is_repeat:
        incident?.isRepeatAttacker ??
        false,

      repeat_count:
        incident?.repeatCount ??
        1,

      // ── Coordination ─────────────────────────────────
      coordinated:
        Boolean(
          incident?.coordinatedAttack
        ),

      affected_prefixes:
        incident?.affectedPrefixes ??
        [],

      // ── Response ─────────────────────────────────────
      countermeasures_ready:
        incident?.countermeasuresReady ??
        false,

      // ── RPKI ─────────────────────────────────────────
      rpki_state:
        incident?.rpkiStatus?.valid
          ? 'valid'
          : incident?.rpkiStatus?.invalid
            ? 'invalid'
            : incident?.rpkiStatus?.state === 'not-found'
              ? 'not-found'
              : 'unknown',

      // ── Deterministic detection summary ──────────────
      summary:
        incident?.deterministicSummary ??
        '',

      // ── BGP-specific information ─────────────────────
      prepend_count:
        incident?.prependCount ??
        0,

      unique_hops:
        incident?.uniqueHops ??
        0,

      has_loop:
        Boolean(
          incident?.hasLoop
        ),

      has_blackhole_community:
        Boolean(
          incident?.hasBlackholeComm
        ),

      has_suspicious_community:
        Boolean(
          incident?.hasSuspiciousCommunity
        ),

      communities:
        incident?.communities ??
        [],
    }


    const data = await post(
      '/api/analyze',
      {
        context: bgpContext,
      }
    )


    const text =
      data?.analysis ??
      ''


    // ─────────────────────────────────────────────
    // Determine AI-reported severity
    // ─────────────────────────────────────────────

    const isCritical =
      /CRITICAL/i.test(text)

    const isHigh =
      /HIGH/i.test(text) ||
      /WARNING/i.test(text)


    const threatLevel =
      isCritical
        ? 'CRITICAL'
        : isHigh
          ? 'HIGH'
          : 'MEDIUM'


    // ─────────────────────────────────────────────
    // Extract reasoning
    // ─────────────────────────────────────────────

    const whatHappenedLine =
      text
        .split('\n')
        .find(line =>
          line
            .trim()
            .toUpperCase()
            .startsWith('WHAT HAPPENED')
        )


    const reasoning =
      whatHappenedLine
        ? whatHappenedLine
            .replace(
              /^WHAT HAPPENED\s*:?\s*/i,
              ''
            )
            .slice(0, 500)

        : text
            .split('\n')
            .find(line =>
              line.trim().length > 0
            )
            ?.slice(0, 500)

          ?? text.slice(0, 500)


    // ─────────────────────────────────────────────
    // Return compatible decision object
    // ─────────────────────────────────────────────

    return {
      mode: 'autonomous',

      threatLevel,

      attackConfirmed:
        true,

      reasoning,

      rawReport:
        text,

      severity:
        threatLevel,

      _source:
        'hexasentinel-llama-npu',
    }

  } catch (error) {

    console.warn(
      '[Hexa Sentinel] getDecision failed:',
      error?.message
    )

    return null
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 5. generateCERTInReport
// ─────────────────────────────────────────────────────────────────────────────
//
// Replacement for generateCERTInReport()
//
// Used by:
//   src/components/detail/ForensicsReport.jsx
// ─────────────────────────────────────────────────────────────────────────────

export async function generateCERTInReport(
  incident,
  analysis,
  _unused,
  signal
) {
  try {

    const data = await post(
      '/api/reports/certin',
      {
        incident,
        analysis,
      },
      signal
    )

    return data

  } catch (error) {

    if (error?.name === 'AbortError') {
      throw error
    }

    console.warn(
      '[Hexa Sentinel] generateCERTInReport failed:',
      error?.message
    )

    return {
      id: 'N/A',

      text:
        OFFLINE_MSG,

      generatedAt:
        new Date().toISOString(),
    }
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 6. generateISPNotification
// ─────────────────────────────────────────────────────────────────────────────
//
// Replacement for generateISPNotification()
//
// Used by:
//   src/components/detail/ForensicsReport.jsx
//   src/components/detail/ResponseActions.jsx
// ─────────────────────────────────────────────────────────────────────────────

export async function generateISPNotification(
  incident,
  analysis,
  _unused,
  signal
) {
  try {

    const data = await post(
      '/api/reports/isp',
      {
        incident,
        analysis,
      },
      signal
    )

    return (
      data?.text ??
      OFFLINE_MSG
    )

  } catch (error) {

    if (error?.name === 'AbortError') {
      throw error
    }

    console.warn(
      '[Hexa Sentinel] generateISPNotification failed:',
      error?.message
    )

    return OFFLINE_MSG
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 7. connectThreatStream
// ─────────────────────────────────────────────────────────────────────────────
//
// Connects to the local FastAPI WebSocket.
//
// Backend:
//   ws://127.0.0.1:8000/ws
//
// Events:
//   threat
//   heartbeat
//   status
//   etc.
// ─────────────────────────────────────────────────────────────────────────────

export function connectThreatStream(
  onEvent,
  onStatusChange
) {
  const url =
    BASE
      .replace(/^http:/, 'ws:')
      .replace(/^https:/, 'wss:') +
    '/ws'


  let ws = null

  let reconnectTimer = null

  let manuallyClosed = false


  function clearHeartbeat() {
    if (
      ws?._pingInterval
    ) {
      clearInterval(
        ws._pingInterval
      )

      ws._pingInterval = null
    }
  }


  function connect() {

    if (manuallyClosed) {
      return
    }


    try {

      ws = new WebSocket(url)

    } catch (error) {

      console.warn(
        '[Hexa Sentinel] WebSocket creation failed:',
        error?.message
      )

      onStatusChange?.(
        'error'
      )

      scheduleReconnect()

      return
    }


    ws.onopen = () => {

      console.log(
        '[Hexa Sentinel] WebSocket connected — live threat stream active'
      )

      onStatusChange?.(
        'connected'
      )


      // Keep local connection alive.
      ws._pingInterval =
        setInterval(() => {

          if (
            ws?.readyState ===
            WebSocket.OPEN
          ) {
            ws.send('ping')
          }

        }, 25000)
    }


    ws.onmessage = event => {

      try {

        const parsed =
          JSON.parse(
            event.data
          )


        onEvent?.(
          parsed
        )


        // Hexa Sentinel event bus.
        //
        // Components such as SeverityMeter,
        // NPUStatusBadge, etc. can listen for:
        //
        // window.addEventListener(
        //   'hexasentinel:threat',
        //   handler
        // )

        window.dispatchEvent(
          new CustomEvent(
            'hexasentinel:threat',
            {
              detail: parsed,
            }
          )
        )

      } catch (error) {

        console.warn(
          '[Hexa Sentinel] Ignoring malformed WebSocket event'
        )
      }
    }


    ws.onclose = () => {

      clearHeartbeat()

      onStatusChange?.(
        'disconnected'
      )


      if (!manuallyClosed) {

        console.warn(
          '[Hexa Sentinel] WebSocket closed — retrying in 5 seconds'
        )

        scheduleReconnect()
      }
    }


    ws.onerror = () => {

      console.warn(
        '[Hexa Sentinel] WebSocket error — backend may not be running'
      )

      onStatusChange?.(
        'error'
      )
    }
  }


  function scheduleReconnect() {

    if (manuallyClosed) {
      return
    }

    if (reconnectTimer) {
      clearTimeout(
        reconnectTimer
      )
    }


    reconnectTimer =
      setTimeout(
        () => {
          reconnectTimer = null
          connect()
        },
        5000
      )
  }


  connect()


  // ─────────────────────────────────────────────
  // Public connection controller
  // ─────────────────────────────────────────────

  return {

    close() {

      manuallyClosed = true

      if (reconnectTimer) {
        clearTimeout(
          reconnectTimer
        )

        reconnectTimer = null
      }

      clearHeartbeat()


      if (ws) {

        ws.onclose = null
        ws.onerror = null
        ws.close()

        ws = null
      }

      onStatusChange?.(
        'disconnected'
      )
    },
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 8. checkHealth
// ─────────────────────────────────────────────────────────────────────────────
//
// Checks whether the local Hexa Sentinel backend is alive.
//
// Expected backend endpoint:
//   GET /api/health
// ─────────────────────────────────────────────────────────────────────────────

export async function checkHealth() {

  try {

    const response =
      await fetch(
        `${BASE}/api/health`,
        {
          signal:
            AbortSignal.timeout(3000),
        }
      )


    if (!response.ok) {
      return null
    }


    return await response.json()

  } catch {

    return null
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// 9. Backward-compatible aliases
// ─────────────────────────────────────────────────────────────────────────────
//
// These prevent old imports from immediately breaking while you migrate
// the rest of the project from SnapShield → Hexa Sentinel.
//
// You can remove these later after updating every import.
// ─────────────────────────────────────────────────────────────────────────────

export const analyzeIncident =
  analyzeIncidentLocal

export const autonomousDecision =
  getDecision
