import { useState, useEffect, lazy, Suspense } from 'react'
import NPUStatusBadge from '../shared/NPUStatusBadge.jsx'
import SeverityMeter from '../shared/SeverityMeter.jsx'
import {
  useHexaSentinelStore,
  useProfileStore,
} from '../../store/useHexaSentinelStore.js'
import NotificationsPanel from '../panels/NotificationsPanel.jsx'
import ProfilePanel from '../panels/ProfilePanel.jsx'

// Code-split: these are full-screen panels only opened on click.
// They are not needed for first paint, so they stay out of the
// main bundle until the user opens them.
const AttackHistoryPanel = lazy(() =>
  import('../panels/AttackHistoryPanel.jsx')
)

const RouteMonitorPanel = lazy(() =>
  import('../panels/RouteMonitorPanel.jsx')
)

const RPKIGapPanel = lazy(() =>
  import('../panels/RPKIGapPanel.jsx')
)

const AdminChatPanel = lazy(() =>
  import('../panels/AdminChatPanel.jsx')
)

const ChangeHistoryPanel = lazy(() =>
  import('../panels/ChangeHistoryPanel.jsx')
)

function PanelFallback() {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 200,
        background: 'rgba(4,7,14,0.97)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--text-muted)',
        letterSpacing: 1,
      }}
    >
      LOADING…
    </div>
  )
}

export default function TopNav({ onBreachClick }) {
  const systemTime = useHexaSentinelStore(
    s => s.systemTime
  )

  const risStatus = useHexaSentinelStore(
    s => s.risStatus
  )

  const appMode = useHexaSentinelStore(
    s => s.appMode
  )

  const setAppMode = useHexaSentinelStore(
    s => s.setAppMode
  )

  const notifications = useHexaSentinelStore(
    s => s.notifications
  )

  const profile = useProfileStore()

  const [showNotif, setShowNotif] = useState(false)
  const [showProfile, setShowProfile] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showMonitor, setShowMonitor] = useState(false)
  const [showGapScan, setShowGapScan] = useState(false)
  const [showChat, setShowChat] = useState(false)
  const [showChangeLog, setShowChangeLog] = useState(false)

  const changeHistory = useHexaSentinelStore(
    s => s.changeHistory
  )

  const isPaused = useHexaSentinelStore(
    s => s.isPaused
  )

  const pauseSession = useHexaSentinelStore(
    s => s.pauseSession
  )

  const resumeSession = useHexaSentinelStore(
    s => s.resumeSession
  )

  /*
   * Dev/demo aid — reload the application so the recovery
   * flow can be demonstrated without requiring an actual crash.
   *
   * HexaSentinel's persisted Zustand state handles recovery
   * after the page reload.
   */
  function handleSimulateInterruption() {
    const ok = window.confirm(
      'Simulate Interruption?\n\n' +
      'This force-kills the current session (like a crash or dropped tab) ' +
      'and reloads the page. On reload, HexaSentinel will detect unfinished ' +
      'work and recover it — watch for the recovery banner.'
    )

    if (!ok) return

    window.location.reload()
  }

  const timeStr =
    new Date(systemTime)
      .toISOString()
      .replace('T', ' ')
      .slice(0, 19) + ' UTC'

  const dateStr =
    new Date(systemTime).toLocaleDateString(
      'en-GB',
      {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      }
    )

  const badge = notifications.length

  // Live threat level from the on-device ONNX classifier.
  const [threatLevel, setThreatLevel] = useState(0)

  useEffect(() => {
    const handler = e => {
      try {
        const d = JSON.parse(
          e.detail ?? '{}'
        )

        // Score S ∈ [0.0, 1.0] → SeverityMeter level 0-100
        const score = d.score ?? 0

        if (score >= 0.85) {
          setThreatLevel(
            Math.round(score * 100)
          )
        } else {
          // Decay toward 0 during normal traffic.
          setThreatLevel(
            level => Math.max(0, level - 8)
          )
        }
      } catch {}
    }

    window.addEventListener(
      'hexasentinel:threat',
      handler
    )

    return () => {
      window.removeEventListener(
        'hexasentinel:threat',
        handler
      )
    }
  }, [])

  return (
    <>
      <nav
        style={{
          height: 64,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 20px',
          borderBottom:
            '1px solid var(--border-subtle)',
          background: '#060c14',
          flexShrink: 0,
          zIndex: 10,
        }}
      >
        {/* LEFT — HexaSentinel logo */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
          }}
        >
          <svg
            width="40"
            height="40"
            viewBox="0 0 40 40"
            fill="none"
          >
            <circle
              cx="20"
              cy="20"
              r="19"
              fill="#0a1520"
              stroke="rgba(0,255,136,0.2)"
              strokeWidth="1"
            />

            <path
              d="M20 8 L28 18 L20 16 L12 18 Z"
              fill="#00ff88"
              opacity="0.9"
            />

            <path
              d="M20 16 L24 24 L20 22 L16 24 Z"
              fill="#00cc66"
              opacity="0.7"
            />

            <circle
              cx="20"
              cy="20"
              r="2"
              fill="#00ff88"
              opacity="0.8"
            />
          </svg>

          <div>
            <div
              style={{
                fontFamily:
                  'var(--font-display)',
                fontSize: 20,
                fontWeight: 900,
                color: '#00ff88',
                letterSpacing: '-0.02em',
                lineHeight: 1,
              }}
            >
              HexaSentinel
            </div>

            <div
              style={{
                fontFamily:
                  'var(--font-mono)',
                fontSize: 8,
                color: '#446644',
                letterSpacing: '0.18em',
                marginTop: 1,
              }}
            >
              BGP THREAT INTELLIGENCE
            </div>
          </div>

          <div
            style={{
              width: 1,
              height: 32,
              background:
                'var(--border-subtle)',
              margin: '0 8px',
            }}
          />

          {/* Live/demo status */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <div
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background:
                  appMode === 'demo'
                    ? '#bf5af2'
                    : risStatus === 'connected'
                    ? 'var(--accent-green)'
                    : risStatus === 'connecting'
                    ? '#ffd60a'
                    : '#666',

                boxShadow:
                  appMode === 'demo'
                    ? '0 0 6px #bf5af2'
                    : risStatus === 'connected'
                    ? '0 0 6px var(--accent-green)'
                    : 'none',
              }}
            />

            <span
              style={{
                fontFamily:
                  'var(--font-mono)',
                fontSize: 9,
                color:
                  appMode === 'demo'
                    ? '#bf5af2'
                    : risStatus === 'connected'
                    ? 'var(--accent-green)'
                    : '#666',
                letterSpacing: '0.1em',
              }}
            >
              {appMode === 'demo'
                ? 'DEMO SESSION — SCRIPTED DATA'
                : risStatus === 'connected'
                ? 'LIVE · 8 VANTAGE POINTS'
                : risStatus === 'connecting'
                ? 'CONNECTING...'
                : 'DISCONNECTED'}
            </span>
          </div>

          <div
            style={{
              width: 1,
              height: 32,
              background:
                'var(--border-subtle)',
              margin: '0 8px',
            }}
          />

          {/* LIVE / DEMO mode switch */}
          <div
            style={{
              display: 'flex',
              border:
                '1px solid var(--border-mid)',
              borderRadius: 4,
              overflow: 'hidden',
            }}
          >
            <button
              onClick={() =>
                setAppMode('live')
              }
              style={{
                fontFamily:
                  'var(--font-mono)',
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: 1,
                padding: '6px 10px',
                cursor: 'pointer',
                border: 'none',
                background:
                  appMode === 'live'
                    ? 'rgba(0,255,136,0.18)'
                    : 'none',
                color:
                  appMode === 'live'
                    ? 'var(--accent-green)'
                    : 'var(--text-muted)',
              }}
            >
              🔴 LIVE
            </button>

            <button
              onClick={() =>
                setAppMode('demo')
              }
              style={{
                fontFamily:
                  'var(--font-mono)',
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: 1,
                padding: '6px 10px',
                cursor: 'pointer',
                border: 'none',
                background:
                  appMode === 'demo'
                    ? 'rgba(191,90,242,0.22)'
                    : 'none',
                color:
                  appMode === 'demo'
                    ? '#bf5af2'
                    : 'var(--text-muted)',
              }}
            >
              🎬 DEMO
            </button>
          </div>

          <div
            style={{
              width: 1,
              height: 32,
              background:
                'var(--border-subtle)',
              margin: '0 8px',
            }}
          />

          {/* Pause / Resume */}
          <button
            onClick={() =>
              isPaused
                ? resumeSession()
                : pauseSession()
            }
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: 1,
              padding: '6px 12px',
              cursor: 'pointer',
              borderRadius: 4,
              background: isPaused
                ? 'rgba(255,214,10,0.15)'
                : 'rgba(255,255,255,0.04)',
              border: `1px solid ${
                isPaused
                  ? '#ffd60a'
                  : 'var(--border-mid)'
              }`,
              color: isPaused
                ? '#ffd60a'
                : 'var(--text-secondary)',
            }}
          >
            {isPaused
              ? '▶ RESUME'
              : '⏸ PAUSE'}
          </button>

          <div
            style={{
              width: 1,
              height: 32,
              background:
                'var(--border-subtle)',
              margin: '0 8px',
            }}
          />

          {/* Quick navigation */}
          <NavBtn
            label="📊 HISTORY"
            onClick={() => {
              setShowHistory(true)
              setShowMonitor(false)
              setShowGapScan(false)
              setShowChat(false)
              setShowChangeLog(false)
              setShowNotif(false)
              setShowProfile(false)
            }}
          />

          <NavBtn
            label="🔍 MONITOR"
            onClick={() => {
              setShowMonitor(true)
              setShowHistory(false)
              setShowGapScan(false)
              setShowChat(false)
              setShowChangeLog(false)
              setShowNotif(false)
              setShowProfile(false)
            }}
          />

          <NavBtn
            label="🛡 RPKI GAPS"
            onClick={() => {
              setShowGapScan(true)
              setShowHistory(false)
              setShowMonitor(false)
              setShowChat(false)
              setShowChangeLog(false)
              setShowNotif(false)
              setShowProfile(false)
            }}
          />

          <NavBtn
            label="🤖 AI CHAT"
            onClick={() => {
              setShowChat(true)
              setShowHistory(false)
              setShowMonitor(false)
              setShowGapScan(false)
              setShowChangeLog(false)
              setShowNotif(false)
              setShowProfile(false)
            }}
          />

          <NavBtn
            label={`🕘 CHANGE LOG${
              changeHistory.length
                ? ` (${changeHistory.length})`
                : ''
            }`}
            onClick={() => {
              setShowChangeLog(true)
              setShowHistory(false)
              setShowMonitor(false)
              setShowGapScan(false)
              setShowChat(false)
              setShowNotif(false)
              setShowProfile(false)
            }}
          />
        </div>

        {/* CENTER — clock */}
        <div
          style={{
            textAlign: 'center',
          }}
        >
          <div
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 16,
              fontWeight: 700,
              color:
                'var(--text-primary)',
              letterSpacing: '0.05em',
            }}
          >
            {timeStr.slice(11)}
          </div>

          <div
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 9,
              color:
                'var(--text-muted)',
              letterSpacing: '0.1em',
              marginTop: 1,
            }}
          >
            {dateStr}
          </div>
        </div>

        {/* RIGHT */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}
        >
          <NPUStatusBadge />

          <div
            style={{
              width: 1,
              height: 24,
              background:
                'var(--border-subtle)',
            }}
          />

          <SeverityMeter
            level={threatLevel}
            compact={true}
          />

          <div
            style={{
              width: 1,
              height: 24,
              background:
                'var(--border-subtle)',
            }}
          />

          {/* Breach simulation is only available in Demo Mode. */}
          <button
            onClick={
              appMode === 'demo'
                ? onBreachClick
                : undefined
            }
            disabled={appMode !== 'demo'}
            title={
              appMode !== 'demo'
                ? 'Only available in Demo Mode — Live Mode uses real data only'
                : undefined
            }
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: '0.12em',
              color:
                appMode === 'demo'
                  ? '#ff2d55'
                  : '#664444',
              background:
                appMode === 'demo'
                  ? 'rgba(255,45,85,0.08)'
                  : 'rgba(255,45,85,0.03)',
              border: `1px solid ${
                appMode === 'demo'
                  ? 'rgba(255,45,85,0.3)'
                  : 'rgba(255,45,85,0.12)'
              }`,
              borderRadius: 4,
              padding: '6px 14px',
              transition: 'all 0.15s',
              cursor:
                appMode === 'demo'
                  ? 'pointer'
                  : 'not-allowed',
              opacity:
                appMode === 'demo'
                  ? 1
                  : 0.5,
            }}
            onMouseEnter={e => {
              if (appMode === 'demo') {
                e.currentTarget.style.background =
                  'rgba(255,45,85,0.2)'
              }
            }}
            onMouseLeave={e => {
              if (appMode === 'demo') {
                e.currentTarget.style.background =
                  'rgba(255,45,85,0.08)'
              }
            }}
          >
            ⚡ SIMULATE BREACH
          </button>

          {/* Simulate interruption — safe in either mode. */}
          <button
            onClick={handleSimulateInterruption}
            style={{
              fontFamily:
                'var(--font-mono)',
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: '0.12em',
              color: '#ffd60a',
              background:
                'rgba(255,214,10,0.08)',
              border:
                '1px solid rgba(255,214,10,0.3)',
              borderRadius: 4,
              padding: '6px 14px',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background =
                'rgba(255,214,10,0.2)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background =
                'rgba(255,214,10,0.08)'
            }}
            title="Force-kill the session and reload to demonstrate recovery"
          >
            🛟 SIMULATE INTERRUPTION
          </button>

          {/* Notifications */}
          <div
            style={{
              position: 'relative',
              cursor: 'pointer',
            }}
            onClick={() => {
              setShowNotif(!showNotif)
              setShowProfile(false)
            }}
          >
            <div
              style={{
                width: 34,
                height: 34,
                borderRadius: '50%',
                background: showNotif
                  ? 'rgba(0,255,136,0.1)'
                  : 'rgba(255,255,255,0.04)',
                border: `1px solid ${
                  showNotif
                    ? 'var(--accent-green)'
                    : 'var(--border-subtle)'
                }`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.15s',
              }}
            >
              <span style={{ fontSize: 15 }}>
                🔔
              </span>
            </div>

            {badge > 0 && (
              <div
                style={{
                  position: 'absolute',
                  top: -2,
                  right: -2,
                  width: 16,
                  height: 16,
                  borderRadius: '50%',
                  background: '#ff2d55',
                  border:
                    '1.5px solid #060c14',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontFamily:
                    'var(--font-mono)',
                  fontSize: 8,
                  color: '#fff',
                  fontWeight: 700,
                }}
              >
                {badge > 9 ? '9+' : badge}
              </div>
            )}
          </div>

          {/* Settings */}
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: '50%',
              background:
                'rgba(255,255,255,0.04)',
              border:
                '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
            }}
          >
            <span style={{ fontSize: 15 }}>
              ⚙️
            </span>
          </div>

          {/* Profile */}
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: '50%',
              background: showProfile
                ? 'rgba(0,255,136,0.15)'
                : 'rgba(0,255,136,0.08)',
              border: `1px solid ${
                showProfile
                  ? 'var(--accent-green)'
                  : 'rgba(0,255,136,0.2)'
              }`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              overflow: 'hidden',
              transition: 'all 0.15s',
            }}
            onClick={() => {
              setShowProfile(!showProfile)
              setShowNotif(false)
            }}
          >
            {profile.photo ? (
              <img
                src={profile.photo}
                alt="profile"
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                }}
              />
            ) : (
              <span
                style={{
                  fontFamily:
                    'var(--font-mono)',
                  fontSize: 12,
                  color:
                    'var(--accent-green)',
                  fontWeight: 700,
                }}
              >
                {(profile.name?.[0] ?? 'H').toUpperCase()}
              </span>
            )}
          </div>
        </div>
      </nav>

      {/* Panels */}
      {showNotif && (
        <NotificationsPanel
          onClose={() => setShowNotif(false)}
        />
      )}

      {showProfile && (
        <ProfilePanel
          onClose={() => setShowProfile(false)}
        />
      )}

      {showHistory && (
        <Suspense fallback={<PanelFallback />}>
          <AttackHistoryPanel
            onClose={() =>
              setShowHistory(false)
            }
          />
        </Suspense>
      )}

      {showMonitor && (
        <Suspense fallback={<PanelFallback />}>
          <RouteMonitorPanel
            onClose={() =>
              setShowMonitor(false)
            }
          />
        </Suspense>
      )}

      {showGapScan && (
        <Suspense fallback={<PanelFallback />}>
          <RPKIGapPanel
            onClose={() =>
              setShowGapScan(false)
            }
          />
        </Suspense>
      )}

      {showChat && (
        <Suspense fallback={<PanelFallback />}>
          <AdminChatPanel
            onClose={() =>
              setShowChat(false)
            }
          />
        </Suspense>
      )}

      {showChangeLog && (
        <Suspense fallback={<PanelFallback />}>
          <ChangeHistoryPanel
            onClose={() =>
              setShowChangeLog(false)
            }
          />
        </Suspense>
      )}
    </>
  )
}

function NavBtn({ label, onClick }) {
  const [h, setH] = useState(false)

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 8,
        fontWeight: 700,
        letterSpacing: '0.08em',
        color: h
          ? 'var(--accent-green)'
          : 'var(--text-muted)',
        background: h
          ? 'rgba(0,255,136,0.08)'
          : 'none',
        border: `1px solid ${
          h
            ? 'rgba(0,255,136,0.2)'
            : 'var(--border-subtle)'
        }`,
        borderRadius: 3,
        padding: '4px 10px',
        cursor: 'pointer',
        transition: 'all 0.15s',
      }}
    >
      {label}
    </button>
  )
}
