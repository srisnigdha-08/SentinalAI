import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import Panel from '../Panel.jsx'
import { KIND_META, STATUS_META, TERMINATION_LABEL, fmt, interval, trialRows, trialsCsv, evidenceJson } from '../../utils/deceptionArena.js'
import { dateText, timeText } from '../../utils/reportingTime.js'

const mono = { fontFamily: 'Share Tech Mono,monospace' }
const sub = { ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1 }
export const btn = {
  background: 'transparent', border: '1px solid #1a4a6e', color: '#7ab3cc', borderRadius: 2,
  fontFamily: 'Rajdhani,sans-serif', fontWeight: 700, fontSize: 12, letterSpacing: 1,
  padding: '7px 12px', cursor: 'pointer', textTransform: 'uppercase',
}
const COLORS = { STATIC: '#7ab3cc', ADAPTIVE: '#00d4ff' }
const stamp = (v) => {
  const t = Date.parse(v)
  return Number.isFinite(t) ? `${dateText(t)} ${timeText(t)}` : 'Not recorded'
}

export function Badge({ meta, children }) {
  return (
    <span style={{ display: 'inline-flex', gap: 5, alignItems: 'center', ...mono, fontSize: 10, letterSpacing: 1, padding: '2px 8px', color: meta.color, border: `1px solid ${meta.color}66`, background: `${meta.color}14`, whiteSpace: 'nowrap' }}>
      {meta.icon && <span aria-hidden="true">{meta.icon}</span>}
      {children || meta.label.toUpperCase()}
    </span>
  )
}

const TT = ({ active, payload, label }) => active && payload?.length ? (
  <div style={{ background: '#081f35', border: '1px solid #0d3352', padding: '6px 10px', ...mono, fontSize: 11 }}>
    <div style={{ color: '#7ab3cc' }}>Trial {label}</div>
    {payload.map((p) => <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value ?? 'not measured'}</div>)}
  </div>
) : null

function TrialChart({ title, rows, unit, testId }) {
  return (
    <Panel title={title} badge={`${rows.length} PAIRS · RAW`} badgeType="info">
      <div data-testid={testId} style={{ width: '100%', height: 220 }}>
        <ResponsiveContainer>
          <BarChart data={rows} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
            <CartesianGrid stroke="#0d3352" strokeDasharray="3 3" />
            <XAxis dataKey="trial" stroke="#3a6a88" tick={{ fontSize: 10 }} label={{ value: 'trial pair', position: 'insideBottom', offset: -2, fill: '#3a6a88', fontSize: 10 }} />
            <YAxis stroke="#3a6a88" tick={{ fontSize: 10 }} unit={unit} allowDecimals={false} />
            <Tooltip content={<TT />} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="STATIC" name="Static" fill={COLORS.STATIC} isAnimationActive={false} />
            <Bar dataKey="ADAPTIVE" name="Adaptive" fill={COLORS.ADAPTIVE} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div style={{ ...mono, fontSize: 10, color: '#3a6a88' }}>Each bar is one recorded trial, not an average.</div>
    </Panel>
  )
}

function StrategyCard({ name, s, persona, testId }) {
  const row = (k, v) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '4px 0', borderBottom: '1px solid rgba(13,51,82,.5)', fontSize: 13 }}>
      <span style={{ color: '#7ab3cc' }}>{k}</span><span style={{ ...mono, textAlign: 'right' }}>{v}</span>
    </div>
  )
  const d = s.durationSeconds
  const c = s.commands
  return (
    <div data-testid={testId} style={{ background: '#081f35', border: `1px solid ${COLORS[name]}55`, borderTop: `3px solid ${COLORS[name]}`, padding: '1rem', minWidth: 0 }}>
      <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 13, letterSpacing: 2, color: COLORS[name], marginBottom: 6 }}>{name === 'STATIC' ? 'STATIC HONEYPOT' : 'ADAPTIVE HONEYPOT'}</div>
      <div style={{ fontSize: 12, color: '#7ab3cc', marginBottom: 8 }}>{persona}</div>
      {!s.trials ? (
        <div style={{ fontSize: 13, color: '#7ab3cc' }}>Not run in this experiment.</div>
      ) : (<>
        {row('Trials recorded', s.trials)}
        {row('Session duration (mean / median)', d.n ? `${d.mean} s / ${d.median} s` : 'Not measured')}
        {row('Duration range', d.n ? `${d.min}–${d.max} s` : 'Not measured')}
        {row('Commands per session (mean / median)', c.n ? `${c.mean} / ${c.median}` : 'Not measured')}
        {row('Unique commands (all trials)', s.uniqueCommandsTotal)}
        {row('MITRE techniques (all trials)', s.techniques.length)}
        {row('Fingerprint checks', `${s.fingerprinted} of ${s.trials}`)}
        {row('Persona switches', s.personaSwitches)}
        {name === 'ADAPTIVE' && row('Recommendations applied', `${s.recommendationsApplied} of ${s.recommendations} (${s.explorations} exploratory)`)}
        {row('Learner reward (mean)*', fmt(s.reward.mean))}
        {(d.missing > 0 || c.missing > 0) && row('Missing observations', `${d.missing} duration, ${c.missing} commands`)}
        {s.techniques.length > 0 && (
          <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {s.techniques.map((t) => <span key={t.id} title={`${t.name} (derived from commands)`} style={{ ...mono, fontSize: 10, color: '#00d4ff', border: '1px dashed rgba(0,212,255,.4)', padding: '0 5px' }}>◆ {t.id}</span>)}
          </div>
        )}
      </>)}
    </div>
  )
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function ExperimentDetails({ experiment: e, results, canRun, onCancel, cancelling, liveCaveat }) {
  const kind = KIND_META[e.kind] || { label: 'Unknown scenario', color: '#7ab3cc', help: '' }
  const status = STATUS_META[e.status] || STATUS_META.CREATED
  const { summary, comparison, conclusion } = results
  const trials = e.trials || []
  const adaptive = trials.filter((t) => t.strategy === 'ADAPTIVE').sort((a, b) => a.index - b.index)
  const prov = e.provenance || {}
  const small = comparison.commands.pairs > 0 && comparison.commands.pairs < 10
  const personas = Object.entries(summary.ADAPTIVE.personas || {}).map(([p, n]) => `${p} ×${n}`).join(', ')
  const termination = ['completed', 'attacker_left', 'fingerprinted', 'time_limit', 'not_recorded'].map((k) => ({
    k, STATIC: summary.STATIC.terminations[k] || 0, ADAPTIVE: summary.ADAPTIVE.terminations[k] || 0,
  })).filter((r) => r.STATIC || r.ADAPTIVE)

  return (
    <div data-testid="arena-details">
      <Panel style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ minWidth: 0 }}>
            <div style={sub}>EXPERIMENT {e.experimentId}</div>
            <div data-testid="arena-name" style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, overflowWrap: 'anywhere' }}>{e.name}</div>
            {e.description && <div style={{ fontSize: 13, color: '#7ab3cc', marginTop: 4 }}>{e.description}</div>}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
            <Badge meta={status} />
            {e.stalled && <Badge meta={{ color: '#ffaa00', icon: '!' }}>RUNNER NOT REPORTING</Badge>}
            <Badge meta={{ color: kind.color }}>{kind.label.toUpperCase()}</Badge>
            <Badge meta={{ color: '#7ab3cc' }}>REPRODUCIBLE MODE</Badge>
          </div>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
          <button type="button" style={btn} onClick={() => download(`deception-arena-${e.experimentId}.json`, evidenceJson(e, results), 'application/json')}>Export JSON</button>
          <button type="button" style={btn} onClick={() => download(`deception-arena-${e.experimentId}.csv`, trialsCsv(e), 'text/csv')} disabled={!trials.length}>Export CSV</button>
          {canRun && ['CREATED', 'RUNNING'].includes(e.status) && (
            <button type="button" data-testid="arena-cancel" style={{ ...btn, color: '#ffaa00', borderColor: '#ffaa00' }} onClick={onCancel} disabled={cancelling || e.cancelRequested}>
              {e.cancelRequested ? 'Cancel requested' : e.status === 'RUNNING' && !e.stalled ? 'Request stop' : 'Cancel experiment'}
            </button>
          )}
        </div>
        {e.status === 'CREATED' && (
          <div data-testid="arena-runner-hint" style={{ marginTop: 10, fontSize: 12, color: '#7ab3cc', lineHeight: 1.6 }}>
            Waiting for the local runner. In the lab, with <code style={mono}>DECEPTION_ARENA_RUNNER_ENABLED=true</code> on the backend, run:
            <pre style={{ ...mono, fontSize: 11, background: '#020b18', border: '1px solid #0d3352', padding: 8, overflowX: 'auto', margin: '6px 0 0' }}>{`cd ai-engine\npython demo/deception_arena.py --backend http://127.0.0.1:5000 --experiment ${e.experimentId}`}</pre>
          </div>
        )}
        {e.failureReason && <div role="alert" style={{ marginTop: 10, fontSize: 12, color: '#ffaa00' }}>Failure: {e.failureReason}</div>}
      </Panel>

      <Panel title="Result" badge={conclusion.adaptiveBenefitEstablished ? 'BENEFIT ESTABLISHED' : 'NO BENEFIT ESTABLISHED'} badgeType="warn" style={{ marginBottom: '1rem' }}>
        <div data-testid="arena-headline" style={{ fontSize: 16, fontWeight: 600, marginBottom: 10 }}>{conclusion.headline}</div>
        <div data-testid="arena-live-caveat" style={{ fontSize: 13, color: '#ffaa00', marginBottom: 10 }}>{liveCaveat}</div>
        <ul data-testid="arena-findings" style={{ margin: 0, paddingLeft: 0, listStyle: 'none', display: 'grid', gap: 6 }}>
          {conclusion.findings.filter((f) => f.code !== 'LIVE_CAVEAT').map((f) => (
            <li key={f.code} data-code={f.code} style={{ fontSize: 13, borderLeft: `3px solid ${f.level === 'limitation' ? '#ffaa00' : '#00d4ff'}`, paddingLeft: 8 }}>
              <span style={{ ...mono, fontSize: 9, color: f.level === 'limitation' ? '#ffaa00' : '#00d4ff', marginRight: 6 }}>{f.level === 'limitation' ? 'LIMITATION' : 'OBSERVED'}</span>
              {f.text}
            </li>
          ))}
        </ul>
        <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 10 }}>Conclusions are produced by fixed rules from the recorded trials. * The learner reward is the Q-learner’s own score, not an independent outcome.</div>
      </Panel>

      {trials.length === 0 ? (
        <Panel style={{ marginBottom: '1rem' }}><div data-testid="arena-no-trials" style={{ color: '#7ab3cc', fontSize: 13 }}>No trials recorded yet.</div></Panel>
      ) : (<>
        {small && <div role="note" data-testid="arena-small-sample" style={{ ...mono, fontSize: 11, color: '#ffaa00', marginBottom: 8 }}>⚠ SMALL SAMPLE: {comparison.commands.pairs} paired trials. Raw observations only; no difference is claimed.</div>}
        <div className="arena-strategies" style={{ marginBottom: '1rem' }}>
          <StrategyCard testId="arena-static" name="STATIC" s={summary.STATIC} persona={`Fixed persona: ${e.baselinePersona}`} />
          <StrategyCard testId="arena-adaptive" name="ADAPTIVE" s={summary.ADAPTIVE} persona={summary.ADAPTIVE.trials ? `Personas served: ${personas}` : 'Q-learning recommendations'} />
        </div>

        <Panel title="Paired comparison (adaptive − static)" style={{ marginBottom: '1rem' }}>
          <table data-testid="arena-paired" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead><tr style={{ ...sub, textAlign: 'left' }}><th scope="col" style={{ padding: 4 }}>OUTCOME</th><th scope="col" style={{ padding: 4 }}>DIFFERENCE PER PAIR</th><th scope="col" style={{ padding: 4 }}>UNPAIRED</th></tr></thead>
            <tbody>
              {[['Commands per session', comparison.commands], ['Session duration (s)', comparison.durationSeconds], ['MITRE techniques per session', comparison.techniques]].map(([k, p]) => (
                <tr key={k} style={{ borderTop: '1px solid #0d3352' }}><td style={{ padding: 6 }}>{k}</td><td style={{ padding: 6, ...mono }}>{interval(p)}</td><td style={{ padding: 6, ...mono }}>{p.unpaired}</td></tr>
              ))}
            </tbody>
          </table>
          <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 6 }}>Pairs share the same attacker random stream; an interval (paired t, 95%) is only given from 10 pairs.</div>
        </Panel>

        <div className="dashboard-grid dashboard-grid-two" style={{ gap: '1rem', marginBottom: '1rem' }}>
          <TrialChart testId="arena-chart-duration" title="Session duration per trial" unit="s" rows={trialRows(trials, (t) => t.durationSeconds)} />
          <TrialChart testId="arena-chart-commands" title="Commands captured per trial" rows={trialRows(trials, (t) => (Array.isArray(t.commands) ? t.commands.length : null))} />
        </div>
        <div className="dashboard-grid dashboard-grid-two" style={{ gap: '1rem', marginBottom: '1rem' }}>
          <TrialChart testId="arena-chart-unique" title="Unique commands per trial" rows={trialRows(trials, (t) => (Array.isArray(t.commands) ? new Set(t.commands.map((c) => c.command)).size : null))} />
          <Panel title="Session endings" badgeType="info">
            <table data-testid="arena-terminations" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead><tr style={{ ...sub, textAlign: 'left' }}><th scope="col" style={{ padding: 4 }}>ENDING</th><th scope="col" style={{ padding: 4 }}>STATIC</th><th scope="col" style={{ padding: 4 }}>ADAPTIVE</th></tr></thead>
              <tbody>{termination.map((r) => <tr key={r.k} style={{ borderTop: '1px solid #0d3352' }}><td style={{ padding: 6 }}>{TERMINATION_LABEL[r.k]}</td><td style={{ padding: 6, ...mono }}>{r.STATIC}</td><td style={{ padding: 6, ...mono }}>{r.ADAPTIVE}</td></tr>)}</tbody>
            </table>
          </Panel>
        </div>

        <Panel title="Q-learning decisions (adaptive)" badge={`${adaptive.length} DECISIONS`} badgeType="info" style={{ marginBottom: '1rem' }}>
          {adaptive.length === 0 ? (
            <div style={{ fontSize: 13, color: '#7ab3cc' }}>The adaptive strategy was not run.</div>
          ) : (
            <div className="sentinel-table-scroll">
              <table data-testid="arena-decisions" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <caption style={{ position: 'absolute', left: -9999 }}>Recorded learner state, recommendation, applied persona and the session that followed</caption>
                <thead><tr style={{ ...sub, textAlign: 'left' }}>
                  {['TRIAL', 'STATE (PREVIOUS PERSONA)', 'RECOMMENDED', 'APPLIED', 'HOW CHOSEN', 'Q-VALUES FOR STATE', 'OUTCOME THAT FOLLOWED', 'REWARD*'].map((h) => <th key={h} scope="col" style={{ padding: '4px 6px', whiteSpace: 'nowrap' }}>{h}</th>)}
                </tr></thead>
                <tbody>
                  {adaptive.map((t) => {
                    const d = t.decision || {}
                    const q = Object.entries(d.qValues || {}).sort((a, b) => b[1] - a[1]).slice(0, 3)
                    return (
                      <tr key={t.index} style={{ borderTop: '1px solid #0d3352' }}>
                        <td style={{ padding: 6, ...mono }}>{t.index + 1}</td>
                        <td style={{ padding: 6, ...mono }}>{d.state || '—'}</td>
                        <td style={{ padding: 6, ...mono }}>{d.recommendedPersona || '—'}</td>
                        <td style={{ padding: 6, ...mono }}>{d.appliedPersona || '—'}{d.recommendedPersona && d.appliedPersona !== d.recommendedPersona ? ' (differs)' : ''}</td>
                        <td style={{ padding: 6 }}>{d.explored ? `Exploration (ε=${fmt(d.epsilon)})` : `Highest Q-value (${d.policy || 'policy not recorded'})`}</td>
                        <td style={{ padding: 6, ...mono }}>{q.length ? q.map(([k, v]) => `${k} ${v}`).join(' · ') : 'Not recorded'}</td>
                        <td style={{ padding: 6 }}>{(t.commands || []).length} cmds, {fmt(t.durationSeconds, ' s')}, {TERMINATION_LABEL[t.termination] || 'not recorded'}</td>
                        <td style={{ padding: 6, ...mono }}>{fmt(t.reward)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 6, lineHeight: 1.6 }}>
            Shown as recorded by the learner copy: its state is only the previous persona. “Highest Q-value” is the learner’s current estimate, not a proven best persona.
            Recommendation, application and the session that followed are separate records.
          </div>
        </Panel>
      </>)}

      <div className="dashboard-grid dashboard-grid-two" style={{ gap: '1rem', marginBottom: '1rem', alignItems: 'start' }}>
        <Panel title="Configuration & provenance">
          <dl data-testid="arena-config" style={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '4px 12px', fontSize: 13 }}>
            {[
              ['Scenario', `${e.scenario} (${kind.label})`],
              ['What it can show', kind.help],
              ['Baseline persona', e.baselinePersona],
              ['Adaptive strategy', e.adaptiveEnabled ? 'Enabled (existing Q-learner)' : 'Disabled'],
              ['Trials per strategy', e.trialsPerStrategy],
              ['Max trial duration', `${e.maxTrialSeconds} s (simulated session time)`],
              ['Seed', e.seed],
              ['Created', `${stamp(e.createdAt)} by ${e.createdBy?.email || 'unknown'}`],
              ['Learner source', prov.learnerSource || 'Recorded when the run completes'],
              ['Learner at start', prov.learnerStart ? `${prov.learnerStart.policy}, ε=${prov.learnerStart.epsilon}, ${prov.learnerStart.episodes} prior episodes` : 'Not recorded yet'],
              ['Q-table hashes', prov.qTableHashes ? (JSON.stringify(prov.qTableHashes.before) === JSON.stringify(prov.qTableHashes.after) ? 'Unchanged before vs after the run' : 'CHANGED (run marked failed)') : 'Not recorded yet'],
              ['Runner', prov.runnerVersion || '—'],
            ].map(([k, v]) => [<dt key={`${k}-k`} style={sub}>{k.toUpperCase()}</dt>, <dd key={`${k}-v`} style={{ margin: 0, overflowWrap: 'anywhere' }}>{v}</dd>])}
          </dl>
        </Panel>
        <Panel title="Experiment timeline" badge={`${(e.events || []).length} EVENTS`} badgeType="info">
          <ol data-testid="arena-timeline" style={{ listStyle: 'none', margin: 0, padding: 0, maxHeight: 320, overflowY: 'auto' }}>
            {(e.events || []).map((ev, i) => (
              <li key={i} style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: 10, padding: '4px 0', borderBottom: '1px solid rgba(13,51,82,.5)', fontSize: 12 }}>
                <span style={{ ...mono, color: '#7ab3cc' }}>{stamp(ev.at)}</span>
                <span><span style={{ ...mono, fontSize: 10, color: '#00d4ff' }}>{String(ev.type).replace(/_/g, ' ')}</span> {ev.detail}</span>
              </li>
            ))}
          </ol>
          <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 6 }}>Times are when the backend recorded each event. Trial sessions are scripted or simulated, so they have no Cowrie session record to open in the Attack Time Machine.</div>
        </Panel>
      </div>
    </div>
  )
}
