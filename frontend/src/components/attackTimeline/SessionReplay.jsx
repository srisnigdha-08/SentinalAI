import { useEffect, useMemo, useRef, useState } from 'react'
import toast from 'react-hot-toast'
import Panel from '../Panel.jsx'
import SeverityBadge from '../SeverityBadge.jsx'
import EvidenceText from './EvidenceText.js'
import ProvenanceBadge from './ProvenanceBadge.jsx'
import { btn } from './SessionSelector.jsx'
import { usePlayback } from '../../hooks/usePlayback.js'
import { SPEEDS, stepDelay } from '../../utils/playbackEngine.js'
import { dateText, timeText, REPORT_TIME_ZONE } from '../../utils/reportingTime.js'
import {
  PROVENANCE, PROVENANCE_META, TIME_BASIS, buildTimeline, formatDuration, narrative, summarize, techniqueIndex,
} from '../../utils/attackTimeline.js'

const mono = { fontFamily: 'Share Tech Mono,monospace' }
const KIND_ICON = { connection: '⇢', auth: '🔑', command: '›_', close: '⇥', classification: '◆', persona: '🎭', threat: '⚠', alert: '🔔', response: '⚡', containment: '⛨', blocklist: '⊘' }
const stamp = (ms) => (ms === null || ms === undefined ? 'Unknown time' : `${dateText(ms)} ${timeText(ms)}`)
const offset = (ms, start) => {
  if (ms === null || start === null) return ''
  const s = Math.round((ms - start) / 1000)
  return s >= 0 ? `+${formatDuration(s)}` : `−${formatDuration(-s)}`
}
const reducedMotion = () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

function Kpi({ label, value, sub, testId }) {
  return (
    <div data-testid={testId} style={{ background: '#081f35', border: '1px solid #0d3352', borderRadius: 2, padding: '0.9rem 1rem', minWidth: 0 }}>
      <div style={{ ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 2, marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700, color: '#00d4ff', overflowWrap: 'anywhere' }}>{value}</div>
      {sub && <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

function Row({ k, v }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(110px, 38%) 1fr', gap: 8, padding: '5px 0', borderBottom: '1px solid rgba(13,51,82,.5)' }}>
      <dt style={{ ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1, textTransform: 'uppercase' }}>{k}</dt>
      <dd style={{ margin: 0, fontSize: 13, overflowWrap: 'anywhere' }}>{v === null || v === undefined || v === '' ? <span style={{ color: '#3a6a88' }}>Unavailable</span> : v}</dd>
    </div>
  )
}

function EventDetails({ event, start }) {
  if (!event) return <div style={{ color: '#3a6a88', ...mono, fontSize: 12 }}>Select an event to inspect its recorded evidence.</div>
  const d = event.detail || {}
  const pct = (v) => (Number.isFinite(v) ? `${Math.round(v * 100)}%` : null)
  return (
    <div data-testid="atm-event-details">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center', marginBottom: 10 }}>
        <ProvenanceBadge provenance={event.provenance} />
        <span style={{ ...mono, fontSize: 10, color: '#7ab3cc', border: '1px solid #1a4a6e', padding: '2px 6px' }}>
          {event.link === 'threat' ? 'LINKED VIA THREAT RECORD' : 'THIS SESSION'}
        </span>
      </div>
      <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 13, color: '#c8e6f5', marginBottom: 10 }}>{event.title}</div>
      <dl style={{ margin: 0 }}>
        <Row k={TIME_BASIS[event.basis] || 'Time'} v={event.time === null ? 'Unknown time (not recorded for this item)' : `${stamp(event.time)} (${REPORT_TIME_ZONE}) ${offset(event.time, start)}`} />
        {event.kind === 'connection' && (<>
          <Row k="Session ID" v={<EvidenceText text={d.sessionId} />} />
          <Row k="Source" v={d.sourceIP ? `${d.sourceIP}${d.sourcePort ? `:${d.sourcePort}` : ''}` : null} />
          <Row k="Honeypot node" v={d.honeypotNode} />
          <Row k="SSH client" v={d.clientVersion ? <EvidenceText text={d.clientVersion} /> : null} />
          <Row k="HASSH" v={d.hassh ? <EvidenceText text={d.hassh} /> : null} />
        </>)}
        {event.kind === 'auth' && (<>
          <Row k="Attempt" v={`#${d.attempt}`} />
          <Row k="Username" v={d.username !== undefined ? <EvidenceText text={d.username} /> : 'Hidden for your role'} />
          <Row k="Outcome" v={d.outcome === 'success' ? '✔ Success (recorded)' : '✖ Failure (recorded)'} />
          <Row k="Password" v="Never stored or displayed" />
        </>)}
        {event.kind === 'command' && (<>
          <Row k="Command #" v={d.index} />
          <Row k="Command" v={<EvidenceText testId="atm-detail-command" text={event.command} />} />
          <Row k="Intent" v={d.intent} />
          <Row k="Output" v={d.output ? <EvidenceText block text={d.output} /> : 'No output recorded'} />
        </>)}
        {event.kind === 'close' && (<>
          <Row k="Final status" v={d.status} />
          <Row k="Duration" v={Number.isFinite(d.durationSeconds) ? formatDuration(d.durationSeconds) : null} />
        </>)}
        {event.kind === 'classification' && (<>
          <Row k="Classification" v={d.classification} />
          <Row k="Threat score" v={pct(d.threatScore)} />
          <Row k="Source" v={d.ruleBased ? `Rule-based (${d.method || 'honeypot_rules'})` : d.method} />
          <Row k="Model / rules version" v={d.modelVersion} />
          <Row k="Explanation" v={d.explanation} />
        </>)}
        {event.kind === 'persona' && (<>
          <Row k="Persona served" v={d.servedProfile} />
          <Row k="Next recommended" v={d.recommendedProfile} />
          <Row k="Deception score" v={Number.isFinite(d.deceptionScore) ? `${d.deceptionScore} / 100` : null} />
          <Row k="Q-learner reward" v={Number.isFinite(d.qDeceptionScore) && d.qDeceptionScore ? d.qDeceptionScore : null} />
        </>)}
        {event.kind === 'threat' && (<>
          <Row k="Severity" v={d.severity ? <SeverityBadge sev={d.severity} /> : null} />
          <Row k="Score" v={pct(d.aiScore)} />
          <Row k="Status" v={d.status} />
          <Row k="Note" v={d.note} />
        </>)}
        {event.kind === 'alert' && (<>
          <Row k="Severity" v={d.severity} />
          <Row k="Type" v={d.type} />
          <Row k="Message" v={d.message ? <EvidenceText block text={d.message} /> : null} />
        </>)}
        {event.kind === 'response' && (<><Row k="Action" v={d.actionType} /><Row k="Note" v={d.note} /></>)}
        {event.kind === 'containment' && (<>
          <Row k="Containment ID" v={d.containmentId ? <EvidenceText text={d.containmentId} /> : null} />
          <Row k="Transition" v={d.transition || d.status} />
          <Row k="Current state" v={d.currentStatus} />
          <Row k="Enforcement" v={d.enforcement} />
          <Row k="Policy decision" v={d.policyDecision} />
          <Row k="Action" v={d.actionType} />
          <Row k="Target" v={d.target} />
          <Row k="Rollback" v={d.rolledBackAt ? `Rolled back ${stamp(Date.parse(d.rolledBackAt))}` : 'Not rolled back'} />
          <Row k="Failure" v={d.failureReason} />
        </>)}
        {event.kind === 'blocklist' && (<><Row k="Reason" v={d.reason} /><Row k="Note" v={d.note} /></>)}
      </dl>
      {event.techniques?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1, marginBottom: 6 }}>
            MITRE ATT&CK (DERIVED FROM {event.kind === 'command' ? 'THIS COMMAND' : 'THIS RECORD'})
          </div>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {event.techniques.map((t) => (
              <li key={t.id} style={{ ...mono, fontSize: 11, color: '#00d4ff', border: '1px solid rgba(0,212,255,.3)', padding: '2px 6px' }}>
                ◆ {t.id} <span style={{ color: '#7ab3cc' }}>{t.name}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default function SessionReplay({ evidence, onBack, live }) {
  const session = evidence.session
  const { events, untimed } = useMemo(() => buildTimeline(evidence), [evidence])
  const summary = useMemo(() => summarize(evidence, events, untimed), [evidence, events, untimed])
  const techniques = useMemo(() => techniqueIndex([...events, ...untimed], session), [events, untimed, session])
  const [state, player] = usePlayback(events)
  const [pinned, setPinned] = useState(null)
  const [techFilter, setTechFilter] = useState(null)
  const listRef = useRef(null)

  const current = state.index >= 0 ? events[state.index] : null
  const shown = pinned || current
  const start = events.find((e) => e.kind === 'connection')?.time ?? events[0]?.time ?? null
  const highlighted = techFilter ? new Set(techniques.find((t) => t.id === techFilter)?.eventIds || []) : null
  const compression = current && state.playing ? stepDelay(events, state.index, state.speed).compressed : false

  useEffect(() => setPinned(null), [state.index])

  // Keep the active event visible while playing; no smooth scrolling when reduced motion is requested.
  useEffect(() => {
    if (!state.playing || !current) return
    const el = listRef.current?.querySelector(`[data-event-id="${CSS.escape(current.id)}"]`)
    el?.scrollIntoView?.({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' })
  }, [state.playing, current])

  const onKeyDown = (e) => {
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(e.target.tagName)) return
    if (e.key === ' ' && e.target.tagName !== 'BUTTON') { e.preventDefault(); player.toggle() }
    else if (e.key === 'ArrowRight') { e.preventDefault(); player.next() }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); player.prev() }
    else if (e.key === 'Home') { e.preventDefault(); player.restart() }
  }

  const copyId = () => {
    navigator.clipboard?.writeText(session.sessionId).then(() => toast.success('Session ID copied'), () => toast.error('Copy failed'))
  }

  return (
    <div onKeyDown={onKeyDown} data-testid="atm-replay">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', marginBottom: '1rem' }}>
        <button type="button" style={btn} onClick={onBack} data-testid="atm-back">← Session list</button>
        <div style={{ ...mono, fontSize: 13, color: '#00d4ff', overflowWrap: 'anywhere' }} data-testid="atm-session-id">{session.sessionId}</div>
        <button type="button" style={{ ...btn, padding: '4px 8px', fontSize: 10 }} onClick={copyId} aria-label="Copy session ID">Copy ID</button>
        <span style={{ ...mono, fontSize: 11, color: '#7ab3cc' }}>{session.sourceIP}</span>
        {live && (
          <span data-testid="atm-live" style={{ ...mono, fontSize: 10, color: '#ff2d55', border: '1px solid rgba(255,45,85,.4)', padding: '2px 8px' }}>
            ● LIVE SESSION: new recorded events are appended
          </span>
        )}
      </div>

      <div className="atm-kpis" style={{ marginBottom: '0.75rem' }}>
        <Kpi testId="atm-kpi-duration" label="DURATION" value={formatDuration(summary.durationSeconds)} sub={session.status === 'active' ? 'Session still active' : null} />
        <Kpi testId="atm-kpi-commands" label="COMMANDS" value={summary.commandsCaptured} sub={summary.commandsCaptured > summary.commandsStored ? `${summary.commandsStored} stored` : null} />
        <Kpi testId="atm-kpi-mitre" label="MITRE TECHNIQUES" value={summary.techniques} sub="Derived from this session" />
        <Kpi label="HIGHEST SEVERITY" value={summary.highestSeverity || 'None linked'} sub={summary.threatScore !== null ? `Rule score ${Math.round(summary.threatScore * 100)}%` : null} />
        <Kpi label="PERSONA" value={summary.persona || 'Not recorded'} />
        <Kpi testId="atm-kpi-status" label="FINAL STATUS" value={(summary.status || 'Unknown').toUpperCase()} />
      </div>
      <p data-testid="atm-narrative" style={{ fontSize: 14, color: '#c8e6f5', margin: '0 0 0.4rem' }}>{narrative(summary)}</p>
      <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginBottom: '1rem' }}>
        Summary composed from the recorded fields above. Playback only animates stored evidence: nothing is executed, sent or changed.
      </div>

      <div role="note" aria-label="Evidence legend" style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: '1rem' }}>
        {Object.keys(PROVENANCE_META).map((p) => (
          <span key={p} style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
            <ProvenanceBadge provenance={p} compact />
            <span style={{ fontSize: 11, color: '#3a6a88' }}>{PROVENANCE_META[p].help}</span>
          </span>
        ))}
      </div>

      {/* Playback controls */}
      <Panel style={{ marginBottom: '1rem' }}>
        <div role="toolbar" aria-label="Playback controls" style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          <button type="button" style={btn} onClick={() => player.restart()} disabled={!state.total} aria-label="Restart from the first event">⏮ Restart</button>
          <button type="button" style={btn} onClick={() => player.prev()} disabled={state.index <= 0} aria-label="Previous event">◀ Prev</button>
          <button
            type="button" data-testid="atm-play"
            style={{ ...btn, color: '#020b18', background: '#00d4ff', borderColor: '#00d4ff', minWidth: 96 }}
            onClick={() => player.toggle()} disabled={!state.total}
            aria-label={state.playing ? 'Pause playback' : 'Play recorded timeline'} aria-pressed={state.playing}
          >
            {state.playing ? '❚❚ Pause' : '▶ Play'}
          </button>
          <button type="button" style={btn} onClick={() => player.next()} disabled={state.index >= state.total - 1} aria-label="Next event">Next ▶</button>
          <div role="group" aria-label="Playback speed" style={{ display: 'flex', gap: 4, marginLeft: 4 }}>
            {SPEEDS.map((s) => (
              <button
                key={s} type="button" aria-pressed={state.speed === s} data-testid={`atm-speed-${s}`}
                onClick={() => player.setSpeed(s)}
                style={{ ...btn, padding: '5px 8px', ...(state.speed === s ? { color: '#00d4ff', borderColor: '#00d4ff', background: 'rgba(0,212,255,.08)' } : {}) }}
              >{s}×</button>
            ))}
          </div>
          <div aria-live="polite" data-testid="atm-position" style={{ ...mono, fontSize: 11, color: '#7ab3cc', marginLeft: 'auto' }}>
            {state.total ? `EVENT ${state.index + 1} / ${state.total}` : 'NO TIMED EVENTS'}
            {current && ` · ${stamp(current.time)}`}
          </div>
        </div>
        <label style={{ display: 'block', marginTop: 10 }}>
          <span style={{ position: 'absolute', left: -9999 }}>Seek to event</span>
          <input
            type="range" data-testid="atm-seek" min={0} max={Math.max(0, state.total - 1)} step={1}
            value={Math.max(0, state.index)} disabled={state.total <= 1}
            onChange={(e) => player.seek(Number(e.target.value))}
            aria-valuetext={current ? `Event ${state.index + 1} of ${state.total}: ${current.title}` : 'No events'}
            style={{ width: '100%', accentColor: '#00d4ff' }}
          />
        </label>
        <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 4 }}>
          Steps follow recorded gaps ÷ speed; gaps over 3 s are compressed to 3 s{compression ? ' (compressing now)' : ''}. Keys: Space play/pause · ← → step · Home restart.
        </div>
      </Panel>

      <div className="dashboard-grid dashboard-grid-two" style={{ gap: '1rem', alignItems: 'start' }}>
        <Panel title="Attack timeline" badge={`${events.length} TIMED`} badgeType="info">
          {events.length === 0 ? (
            <div data-testid="atm-no-events" style={{ color: '#7ab3cc', ...mono, fontSize: 12 }}>
              No event with a recorded timestamp is stored for this session. Items without a time are listed under “Unknown time”.
            </div>
          ) : (
            <ol ref={listRef} data-testid="atm-timeline" aria-label="Recorded events in chronological order" style={{ listStyle: 'none', margin: 0, padding: 0, maxHeight: 560, overflowY: 'auto' }}>
              {events.map((ev, i) => {
                const active = i === state.index
                const dim = highlighted && !highlighted.has(ev.id)
                return (
                  <li key={ev.id} data-event-id={ev.id} style={{ position: 'relative', paddingLeft: 22, opacity: dim ? 0.35 : 1 }}>
                    <span aria-hidden="true" style={{ position: 'absolute', left: 7, top: 0, bottom: 0, width: 2, background: i < state.index ? '#00d4ff' : '#0d3352' }} />
                    <span aria-hidden="true" style={{ position: 'absolute', left: 2, top: 14, width: 12, height: 12, borderRadius: '50%', background: active ? '#00d4ff' : '#081f35', border: `2px solid ${PROVENANCE_META[ev.provenance]?.color || '#7ab3cc'}` }} />
                    <button
                      type="button" className="atm-event" data-testid="atm-event" aria-current={active ? 'step' : undefined}
                      onClick={() => player.seek(i)}
                      style={{
                        display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer', margin: '4px 0', padding: '8px 10px',
                        background: active ? 'rgba(0,212,255,.1)' : 'transparent', color: '#c8e6f5',
                        border: `1px solid ${active ? '#00d4ff' : 'transparent'}`, borderRadius: 2,
                      }}
                    >
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                        <span style={{ ...mono, fontSize: 11, color: '#7ab3cc' }}>{timeText(ev.time)}</span>
                        <span style={{ ...mono, fontSize: 10, color: '#3a6a88' }}>{offset(ev.time, start)}</span>
                        <ProvenanceBadge provenance={ev.provenance} compact />
                        {ev.link === 'threat' && <span style={{ ...mono, fontSize: 9, color: '#7ab3cc' }}>VIA THREAT</span>}
                        {active && <span style={{ ...mono, fontSize: 9, color: '#00d4ff' }}>◀ CURRENT</span>}
                      </div>
                      <div style={{ marginTop: 3, fontSize: 14 }}>
                        <span aria-hidden="true" style={{ marginRight: 6 }}>{KIND_ICON[ev.kind] || '•'}</span>
                        {ev.title}{ev.kind === 'command' && <>: <EvidenceText text={ev.command} maxLength={160} /></>}
                      </div>
                      {ev.techniques.length > 0 && (
                        <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {ev.techniques.map((t) => (
                            <span key={t.id} title={`${t.name} (derived mapping)`} style={{ ...mono, fontSize: 10, color: '#00d4ff', border: '1px dashed rgba(0,212,255,.4)', padding: '0 5px' }}>◆ {t.id}</span>
                          ))}
                        </div>
                      )}
                    </button>
                  </li>
                )
              })}
            </ol>
          )}
        </Panel>

        <div style={{ display: 'grid', gap: '1rem', minWidth: 0 }}>
          <Panel title="Event details" badge={shown ? (shown.time === null ? 'UNKNOWN TIME' : `EVENT ${state.index + 1}`) : undefined} badgeType="info">
            <EventDetails event={shown} start={start} />
          </Panel>

          <Panel title="MITRE ATT&CK" badge={`${techniques.length} TECHNIQUES`} badgeType="info">
            {techniques.length === 0 ? (
              <div data-testid="atm-no-mitre" style={{ color: '#7ab3cc', ...mono, fontSize: 12 }}>No MITRE ATT&CK technique is mapped for this session.</div>
            ) : (
              <>
                <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginBottom: 8 }}>
                  Techniques are derived by SentinelAI’s existing command/intent mapping; the commands themselves are the observed evidence. Select one to highlight its events.
                </div>
                <ul data-testid="atm-mitre" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
                  {techniques.map((t) => {
                    const on = techFilter === t.id
                    return (
                      <li key={t.id}>
                        <button
                          type="button" aria-pressed={on} data-testid="atm-technique"
                          onClick={() => {
                            setTechFilter(on ? null : t.id)
                            const first = events.findIndex((e) => t.eventIds.includes(e.id))
                            if (!on && first >= 0) player.seek(first)
                          }}
                          style={{ ...btn, width: '100%', textAlign: 'left', textTransform: 'none', display: 'flex', gap: 8, alignItems: 'baseline', ...(on ? { borderColor: '#00d4ff', color: '#00d4ff' } : {}) }}
                        >
                          <span style={mono}>◆ {t.id}</span>
                          <span style={{ fontWeight: 500 }}>{t.name}</span>
                          <span style={{ ...mono, fontSize: 10, marginLeft: 'auto', color: '#3a6a88' }}>
                            {t.threatOnly ? 'threat record only · ' : ''}{t.eventIds.length ? `${t.eventIds.length} event${t.eventIds.length > 1 ? 's' : ''}` : 'session-level only'}
                          </span>
                        </button>
                      </li>
                    )
                  })}
                </ul>
              </>
            )}
          </Panel>

          <Panel title="Unknown time" badge={`${untimed.length} ITEMS`} badgeType="warn">
            {untimed.length === 0 ? (
              <div style={{ color: '#3a6a88', ...mono, fontSize: 12 }}>Every recorded item has a timestamp.</div>
            ) : (
              <>
                <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginBottom: 8 }}>
                  Recorded without a usable timestamp (for example, Cowrie login attempts are stored without per-attempt times). They are not placed on the clock.
                </div>
                <ul data-testid="atm-untimed" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 4 }}>
                  {untimed.map((ev) => (
                    <li key={ev.id}>
                      <button type="button" onClick={() => setPinned(ev)} aria-pressed={pinned?.id === ev.id}
                        style={{ ...btn, width: '100%', textAlign: 'left', textTransform: 'none', display: 'flex', gap: 8, alignItems: 'center' }}>
                        <ProvenanceBadge provenance={ev.provenance} compact />
                        <span>{ev.title}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </Panel>

          <Panel title="Defense activity" badgeType="info">
            {!evidence.access?.containmentVisible ? (
              <div style={{ color: '#7ab3cc', ...mono, fontSize: 12 }}>Containment records are available to admin and analyst roles only.</div>
            ) : (evidence.containment || []).length === 0 && (evidence.blockedIPs || []).length === 0 ? (
              <div data-testid="atm-no-response" style={{ color: '#7ab3cc', ...mono, fontSize: 12 }}>
                No containment action or deny-list record is linked to this session’s threat record.
              </div>
            ) : (
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
                {(evidence.containment || []).map((c) => (
                  <li key={c.containmentId} style={{ fontSize: 13 }}>
                    <ProvenanceBadge provenance={c.enforcementBackend === 'mock' || c.enforcementBackend === 'simulated' ? PROVENANCE.SIMULATED : c.enforcementBackend === 'windows-firewall' ? PROVENANCE.OBSERVED : PROVENANCE.UNKNOWN} compact />{' '}
                    {c.actionType} · {c.enforcementStatus} · backend <strong>{c.enforcementBackend}</strong>
                    {(c.enforcementBackend === 'mock' || c.enforcementBackend === 'simulated') && <span style={{ color: '#ffaa00' }}> (no host firewall rule applied)</span>}
                  </li>
                ))}
                {(evidence.blockedIPs || []).map((b) => (
                  <li key={b.ip} style={{ fontSize: 13 }}><ProvenanceBadge provenance={PROVENANCE.DERIVED} compact /> Deny-list entry for {b.ip}</li>
                ))}
              </ul>
            )}
            <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 8 }}>
              Only records that reference this session or its threat record are shown; nothing is matched by source IP alone.
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
