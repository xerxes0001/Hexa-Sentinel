/**
 * HexaSentinel Execution Simulation — DEMO MODE ONLY.
 *
 * Shows the human-in-the-loop authorization step used by HexaSentinel:
 * a network engineer must authorize deployment before any real network
 * change would occur.
 *
 * This panel simulates that authorization and walks through what a
 * deployment workflow would look like. Every operation is explicitly
 * labeled as simulated because HexaSentinel does not directly maintain
 * a production BGP session or autonomously deploy network changes.
 *
 * This component is intended for simulated incidents only.
 */
import { useState, useRef, useEffect } from 'react'
import {
  generateCountermeasures,
  splitPrefix,
} from '../../engine/countermeasureGenerator.js'
import SimulatedDataFlow from './SimulatedDataFlow.jsx'

const STEPS = [
  {
    key: 'roa',
    label: 'Filing RPKI ROA with IRINN',
    doneLabel: 'RPKI ROA filed',
  },
  {
    key: 'rtbh',
    label: 'Pushing RTBH blackhole to IXP route servers',
    doneLabel: 'RTBH blackhole active',
  },
  {
    key: 'flowspec',
    label: 'Deploying BGP Flowspec rule',
    doneLabel: 'Flowspec rule deployed',
  },
  {
    key: 'more',
    label: 'Announcing more-specific prefix',
    doneLabel: 'More-specific prefix announced',
  },
]

const MORE_SPECIFIC_STEP_INDEX = STEPS.findIndex(
  step => step.key === 'more'
)

export default function ExecutionSimulation({ incident }) {
  const [phase, setPhase] = useState('idle')
  // idle | pending | executing | complete

  const [stepIndex, setStepIndex] = useState(-1)

  const timeouts = useRef([])

  useEffect(() => {
    return () => {
      timeouts.current.forEach(clearTimeout)
    }
  }, [])

  const cm = generateCountermeasures(incident)
  const halves = splitPrefix(incident.prefix)

  /*
   * Traffic is considered restored only after the more-specific
   * announcement step completes.
   *
   * This mirrors the longest-prefix-match mechanism represented by
   * the simulation.
   */
  const restored =
    stepIndex >= MORE_SPECIFIC_STEP_INDEX

  function requestAuthorization() {
    setPhase('pending')

    timeouts.current.push(
      setTimeout(() => {
        setPhase('executing')

        STEPS.forEach((_, i) => {
          timeouts.current.push(
            setTimeout(() => {
              setStepIndex(i)
            }, 700 * (i + 1))
          )
        })

        timeouts.current.push(
          setTimeout(() => {
            setPhase('complete')
          }, 700 * (STEPS.length + 1))
        )
      }, 1100)
    )
  }

  function reset() {
    timeouts.current.forEach(clearTimeout)
    timeouts.current = []

    setPhase('idle')
    setStepIndex(-1)
  }

  return (
    <div>

      {/* Simulation disclaimer */}
      <div
        style={{
          padding: '9px 12px',
          marginBottom: 10,
          background: 'rgba(191,90,242,0.06)',
          border: '1px solid rgba(191,90,242,0.3)',
          borderRadius: 4,
        }}
      >
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 8,
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
          }}
        >
          🎬{' '}
          <strong style={{ color: 'var(--accent-purple)' }}>
            HEXASENTINEL SIMULATION — DEMO MODE ONLY.
          </strong>{' '}
          HexaSentinel does not directly maintain a production BGP session
          and does not autonomously deploy network changes. Everything below,
          including the data-flow visualization and countermeasure execution,
          is simulated using the selected incident's synthetic data.
        </div>
      </div>

      {/* 
       * Data-flow visualization.
       *
       * It is visible before execution so the audience can see the
       * simulated attack state and then observe the modeled recovery
       * when the more-specific announcement completes.
       */}
      <SimulatedDataFlow
        incident={incident}
        restored={restored}
        halves={halves}
      />

      {/* Authorization request */}
      {phase === 'idle' && (
        <button
          onClick={requestAuthorization}
          style={{
            width: '100%',
            padding: '10px 0',
            fontFamily: 'var(--font-display)',
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 1,
            background: 'rgba(191,90,242,0.14)',
            border: '1px solid rgba(191,90,242,0.5)',
            color: 'var(--accent-purple)',
            cursor: 'pointer',
            borderRadius: 3,
          }}
        >
          🔐 REQUEST NETWORK ENGINEER AUTHORIZATION
        </button>
      )}

      {/* Authorization pending */}
      {phase === 'pending' && (
        <div
          style={{
            padding: '12px 14px',
            textAlign: 'center',
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: '#ffd60a',
            background: 'rgba(255,214,10,0.06)',
            border: '1px solid rgba(255,214,10,0.3)',
            borderRadius: 4,
          }}
        >
          ⏳ Awaiting network engineer review…
        </div>
      )}

      {/* Execution */}
      {(phase === 'executing' || phase === 'complete') && (
        <div>

          <div
            style={{
              padding: '8px 12px',
              marginBottom: 8,
              background: 'rgba(48,209,88,0.06)',
              border: '1px solid rgba(48,209,88,0.3)',
              borderRadius: 4,
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--accent-green)',
              fontWeight: 700,
            }}
          >
            ✓ AUTHORIZED (SIMULATED) — running HexaSentinel
            countermeasure workflow…
          </div>

          {/* Countermeasure steps */}
          {STEPS.map((step, i) => {
            const done = stepIndex >= i

            return (
              <div
                key={step.key}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '7px 10px',
                  background: done
                    ? 'rgba(0,255,136,0.04)'
                    : 'rgba(255,255,255,0.02)',
                  border: `1px solid ${
                    done
                      ? 'rgba(0,255,136,0.2)'
                      : 'var(--border-subtle)'
                  }`,
                  borderRadius: 3,
                  marginBottom: 5,
                  transition: 'all 0.2s',
                }}
              >

                <div
                  style={{
                    width: 16,
                    height: 16,
                    borderRadius: '50%',
                    flexShrink: 0,
                    border: `1px solid ${
                      done
                        ? 'var(--accent-green)'
                        : 'var(--border-mid)'
                    }`,
                    background: done
                      ? 'rgba(0,255,136,0.15)'
                      : 'none',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {done && (
                    <span
                      style={{
                        color: 'var(--accent-green)',
                        fontSize: 9,
                      }}
                    >
                      ✓
                    </span>
                  )}
                </div>

                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 9,
                    color: done
                      ? 'var(--accent-green)'
                      : 'var(--text-muted)',
                  }}
                >
                  {done ? step.doneLabel : step.label}
                  {!done && stepIndex === i - 1 ? '…' : ''}
                </span>

              </div>
            )
          })}

          {/* Completion */}
          {phase === 'complete' && (
            <div style={{ marginTop: 12 }}>

              <div
                style={{
                  padding: '9px 11px',
                  marginBottom: 10,
                  background: 'rgba(0,255,136,0.05)',
                  border: '1px solid rgba(0,255,136,0.25)',
                  borderRadius: 4,
                }}
              >
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 8,
                    color: 'var(--accent-green)',
                    fontWeight: 700,
                    marginBottom: 4,
                  }}
                >
                  ✓ SIMULATION COMPLETE
                </div>

                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 8,
                    color: 'var(--text-secondary)',
                    lineHeight: 1.6,
                  }}
                >
                  HexaSentinel's modeled countermeasure workflow has
                  completed. No production network configuration was
                  changed by this simulation.
                </div>
              </div>

              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 7.5,
                  color: 'var(--text-muted)',
                  marginBottom: 10,
                  lineHeight: 1.6,
                }}
              >
                BGP uses longest-prefix matching when selecting routes.
                The more-specific announcement shown here therefore
                models how traffic could be redirected away from the
                hijacked aggregate in the simulated scenario.
              </div>

              <button
                onClick={reset}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8,
                  padding: '5px 10px',
                  background: 'none',
                  border: '1px solid var(--border-mid)',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  borderRadius: 2,
                }}
              >
                RESET SIMULATION
              </button>

            </div>
          )}

        </div>
      )}

    </div>
  )
}
