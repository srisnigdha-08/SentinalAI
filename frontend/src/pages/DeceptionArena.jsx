import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import ExperimentDetails, { Badge, btn } from '../components/deceptionArena/ExperimentDetails.jsx'
import { arenaAPI } from '../services/api.js'
import { useAuth } from '../hooks/useAuth.js'
import { KIND_META, STATUS_META } from '../utils/deceptionArena.js'
import { dateText, timeText } from '../utils/reportingTime.js'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const mono = { fontFamily: 'Share Tech Mono,monospace' }
const field = { background: '#020b18', border: '1px solid #1a4a6e', color: '#c8e6f5', borderRadius: 2, padding: '7px 10px', ...mono, fontSize: 12, minWidth: 0 }
const label = { display: 'flex', flexDirection: 'column', gap: 4, ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1 }
const stamp = (v) => {
  const t = Date.parse(v)
  return Number.isFinite(t) ? `${dateText(t)} ${timeText(t)}` : '—'
}

function NewExperiment({ meta, onCreated, onClose }) {
  const [form, setForm] = useState({ name: '', description: '', scenario: meta.scenarios[0]?.id || '', baselinePersona: 'centos_7', trialsPerStrategy: 10, maxTrialSeconds: 600, seed: 1, adaptiveEnabled: true })
  const [errors, setErrors] = useState([])
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }))
  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErrors([])
    try {
      const r = await arenaAPI.create({ ...form, trialsPerStrategy: Number(form.trialsPerStrategy), maxTrialSeconds: Number(form.maxTrialSeconds), seed: Number(form.seed) })
      toast.success('Experiment created')
      onCreated(r.data.data.experiment.experimentId)
    } catch (err) {
      setErrors(err?.response?.data?.errors || [err?.response?.data?.error || 'The experiment could not be created.'])
    } finally {
      setBusy(false)
    }
  }
  const kind = KIND_META[meta.scenarios.find((s) => s.id === form.scenario)?.kind]
  return (
    <Panel title="New experiment" style={{ marginBottom: '1rem' }}>
      <form data-testid="arena-form" onSubmit={submit} style={{ display: 'grid', gap: 10 }}>
        <div className="arena-form-grid">
          <label style={label}>NAME<input data-testid="arena-form-name" style={field} value={form.name} onChange={set('name')} maxLength={80} required /></label>
          <label style={label}>SCENARIO (ALLOWLISTED)
            <select data-testid="arena-form-scenario" style={field} value={form.scenario} onChange={set('scenario')}>
              {meta.scenarios.map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}
            </select>
          </label>
          <label style={label}>STATIC BASELINE PERSONA
            <select style={field} value={form.baselinePersona} onChange={set('baselinePersona')}>
              {meta.personas.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label style={label}>TRIALS PER STRATEGY (1–50)<input type="number" min={1} max={50} style={field} value={form.trialsPerStrategy} onChange={set('trialsPerStrategy')} /></label>
          <label style={label}>MAX TRIAL DURATION, S (30–3600)<input type="number" min={30} max={3600} style={field} value={form.maxTrialSeconds} onChange={set('maxTrialSeconds')} /></label>
          <label style={label}>SEED<input type="number" min={0} style={field} value={form.seed} onChange={set('seed')} /></label>
        </div>
        <label style={label}>DESCRIPTION (OPTIONAL)<input style={field} value={form.description} onChange={set('description')} maxLength={500} /></label>
        <label style={{ ...label, flexDirection: 'row', alignItems: 'center', gap: 8 }}><input type="checkbox" checked={form.adaptiveEnabled} onChange={set('adaptiveEnabled')} /> RUN THE ADAPTIVE (Q-LEARNING) STRATEGY TOO</label>
        {kind && <div style={{ fontSize: 12, color: kind.color }}>{kind.label}: {kind.help}</div>}
        <div style={{ fontSize: 12, color: '#7ab3cc' }}>
          Creating an experiment runs nothing. The local runner executes it against a temporary copy of the Q-learner: no SSH, no Cowrie restart, no command is executed and no Q-table is written.
          {!meta.runnerEnabled && ' The runner is currently disabled on this backend (DECEPTION_ARENA_RUNNER_ENABLED is not true).'}
        </div>
        {errors.length > 0 && <ul role="alert" style={{ margin: 0, color: '#ffaa00', fontSize: 12 }}>{errors.map((x) => <li key={x}>{x}</li>)}</ul>}
        <div style={{ display: 'flex', gap: 8 }}>
          <button type="submit" data-testid="arena-form-submit" style={{ ...btn, color: '#020b18', background: '#00d4ff', borderColor: '#00d4ff' }} disabled={busy}>Create experiment</button>
          <button type="button" style={btn} onClick={onClose}>Close</button>
        </div>
      </form>
    </Panel>
  )
}

function Observational({ data }) {
  if (!data) return null
  return (
    <Panel title="Recorded Cowrie sessions by persona" badge="OBSERVATIONAL" badgeType="warn">
      <div style={{ fontSize: 12, color: '#ffaa00', marginBottom: 8 }}>
        Real sessions from different attackers at different times. Not a controlled comparison: differences between personas here cannot be attributed to the persona.
      </div>
      {data.byPersona.length === 0 ? (
        <div data-testid="arena-obs-empty" style={{ fontSize: 13, color: '#7ab3cc' }}>No recorded session has a served persona yet.</div>
      ) : (
        <table data-testid="arena-observational" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, marginBottom: 10 }}>
          <thead><tr style={{ ...mono, fontSize: 10, color: '#3a6a88', textAlign: 'left' }}><th scope="col" style={{ padding: 4 }}>PERSONA</th><th scope="col" style={{ padding: 4 }}>SESSIONS</th><th scope="col" style={{ padding: 4 }}>OF WHICH SYNTHETIC (DEMO-)</th><th scope="col" style={{ padding: 4 }}>MEAN DURATION</th><th scope="col" style={{ padding: 4 }}>MEAN COMMANDS</th></tr></thead>
          <tbody>{data.byPersona.map((p) => (
            <tr key={p.persona} style={{ borderTop: '1px solid #0d3352' }}><td style={{ padding: 6, ...mono }}>{p.persona}</td><td style={{ padding: 6 }}>{p.sessions}</td><td style={{ padding: 6 }}>{p.synthetic}</td><td style={{ padding: 6 }}>{p.meanDurationSeconds ?? '—'} s</td><td style={{ padding: 6 }}>{p.meanCommands ?? '—'}</td></tr>
          ))}</tbody>
        </table>
      )}
      {data.recent.length > 0 && (
        <ul data-testid="arena-recent-sessions" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 4 }}>
          {data.recent.map((s) => (
            <li key={s._id} style={{ fontSize: 12, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
              <Link to={`/dashboard/attack-time-machine?session=${s._id}`} style={{ ...mono, color: '#00d4ff' }} aria-label={`Replay session ${s.sessionId} in the Attack Time Machine`}>{s.sessionId} ⏪</Link>
              <span style={{ color: '#7ab3cc' }}>{s.servedProfile} · {stamp(s.startTime)} · {s.commandCount} cmds</span>
            </li>
          ))}
        </ul>
      )}
      <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 6 }}>{data.unattributed} recorded session(s) have no served persona and are not shown.</div>
    </Panel>
  )
}

export default function DeceptionArena() {
  const [params, setParams] = useSearchParams()
  const { user } = useAuth()
  const canRun = user?.role === 'admin' || user?.role === 'analyst'
  const selected = UUID.test(params.get('experiment') || '') ? params.get('experiment') : null
  const status = STATUS_META[params.get('status')] ? params.get('status') : ''
  const scenario = params.get('scenario') || ''
  const [meta, setMeta] = useState(null)
  const [obs, setObs] = useState(null)
  const [list, setList] = useState({ loading: true, error: null, rows: [] })
  const [detail, setDetail] = useState({ loading: false, error: null, data: null })
  const [showForm, setShowForm] = useState(false)
  const [reload, setReload] = useState(0)
  const [cancelling, setCancelling] = useState(false)

  useEffect(() => {
    arenaAPI.scenarios().then((r) => setMeta(r.data.data)).catch(() => setMeta(null))
    arenaAPI.observational().then((r) => setObs(r.data.data)).catch(() => setObs(null))
  }, [])

  useEffect(() => {
    let live = true
    setList((l) => ({ ...l, loading: true, error: null }))
    arenaAPI.list({ status: status || undefined, scenario: scenario || undefined, limit: 50 })
      .then((r) => live && setList({ loading: false, error: null, rows: r.data.data || [] }))
      .catch(() => live && setList({ loading: false, error: 'Experiments could not be loaded.', rows: [] }))
    return () => { live = false }
  }, [status, scenario, reload])

  useEffect(() => {
    if (!selected) { setDetail({ loading: false, error: null, data: null }); return undefined }
    let live = true
    setDetail((d) => ({ loading: !d.data || d.data.experiment.experimentId !== selected, error: null, data: d.data?.experiment.experimentId === selected ? d.data : null }))
    arenaAPI.get(selected)
      .then((r) => live && setDetail({ loading: false, error: null, data: r.data.data }))
      .catch((err) => live && setDetail({ loading: false, error: err?.response?.status === 404 ? 'This experiment was not found.' : 'The experiment could not be loaded.', data: null }))
    return () => { live = false }
  }, [selected, reload])

  // A running experiment is refreshed every 5 s while it is open; nothing polls otherwise.
  const running = detail.data && ['CREATED', 'RUNNING'].includes(detail.data.experiment.status)
  useEffect(() => {
    if (!running) return undefined
    const t = setInterval(() => setReload((k) => k + 1), 5000)
    return () => clearInterval(t)
  }, [running])

  const update = (patch) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) (v ? next.set(k, v) : next.delete(k))
    setParams(next)
  }
  const cancel = async () => {
    setCancelling(true)
    try {
      await arenaAPI.cancel(selected)
      toast.success('Cancellation recorded')
      setReload((k) => k + 1)
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Could not cancel')
    } finally {
      setCancelling(false)
    }
  }

  return (
    <DashboardLayout>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700, margin: 0 }}>
          Deception <span style={{ color: '#00d4ff' }}>Arena</span>
        </h1>
        <div style={{ ...mono, fontSize: 11, color: '#3a6a88', marginTop: 6, lineHeight: 1.6 }}>
          Static vs adaptive honeypot. <strong style={{ color: '#7ab3cc' }}>Static</strong> serves one fixed persona.{' '}
          <strong style={{ color: '#7ab3cc' }}>Adaptive</strong> serves the persona SentinelAI’s existing Q-learner recommends after each session.
          Both run the same allowlisted scenario, in pairs that share the same attacker behaviour, with the same limits and measurements.
        </div>
        {meta && (
          <div data-testid="arena-live-mode" role="note" style={{ marginTop: 8, fontSize: 12, color: '#ffaa00' }}>
            {meta.liveCaveat} Live Cowrie mode is not available: {meta.liveMode.reason}
          </div>
        )}
      </div>

      {canRun && meta && (showForm ? (
        <NewExperiment meta={meta} onClose={() => setShowForm(false)} onCreated={(id) => { setShowForm(false); setReload((k) => k + 1); update({ experiment: id }) }} />
      ) : (
        <button type="button" data-testid="arena-new" style={{ ...btn, marginBottom: '1rem', color: '#00d4ff', borderColor: '#00d4ff' }} onClick={() => setShowForm(true)}>+ New experiment</button>
      ))}

      <div className="arena-layout">
        <Panel title="Experiments" badge={`${list.rows.length}`} badgeType="info">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 10 }}>
            <label style={{ ...label, flex: '1 1 120px' }}>STATUS
              <select data-testid="arena-filter-status" style={field} value={status} onChange={(e) => update({ status: e.target.value })}>
                <option value="">All</option>
                {Object.entries(STATUS_META).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
            </label>
            <label style={{ ...label, flex: '1 1 120px' }}>SCENARIO
              <select style={field} value={scenario} onChange={(e) => update({ scenario: e.target.value })}>
                <option value="">All</option>
                {(meta?.scenarios || []).map((s) => <option key={s.id} value={s.id}>{s.title}</option>)}
              </select>
            </label>
          </div>
          {list.error ? (
            <div role="alert" style={{ fontSize: 12, color: '#ffaa00' }}>{list.error} <button type="button" style={btn} onClick={() => setReload((k) => k + 1)}>Retry</button></div>
          ) : list.loading && !list.rows.length ? (
            <div role="status" style={{ ...mono, fontSize: 12, color: '#3a6a88' }}>Loading experiments…</div>
          ) : list.rows.length === 0 ? (
            <div data-testid="arena-empty" style={{ fontSize: 13, color: '#7ab3cc', padding: '1rem 0' }}>
              {status || scenario ? 'No experiment matches these filters.' : 'No experiment has been created yet.'}{canRun && !status && !scenario ? ' Use “New experiment” to define one.' : ''}
            </div>
          ) : (
            <ul data-testid="arena-list" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
              {list.rows.map((x) => (
                <li key={x.experimentId}>
                  <button type="button" data-testid="arena-item" aria-current={selected === x.experimentId ? 'true' : undefined} onClick={() => update({ experiment: x.experimentId })}
                    style={{ width: '100%', textAlign: 'left', cursor: 'pointer', background: selected === x.experimentId ? 'rgba(0,212,255,.08)' : 'transparent', border: `1px solid ${selected === x.experimentId ? '#00d4ff' : '#0d3352'}`, color: '#c8e6f5', padding: '8px 10px', borderRadius: 2 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{x.name}</span>
                      <Badge meta={STATUS_META[x.status]} />
                    </div>
                    <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 4 }}>
                      {KIND_META[x.kind]?.label || x.scenario} · {x.trialCount}/{x.trialsPerStrategy * (x.adaptiveEnabled ? 2 : 1)} trials · {stamp(x.createdAt)}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div style={{ minWidth: 0 }}>
          {!selected ? (
            <Panel><div data-testid="arena-pick" style={{ fontSize: 13, color: '#7ab3cc' }}>Select an experiment to see its side-by-side results, decisions and evidence.</div></Panel>
          ) : detail.loading ? (
            <div role="status" style={{ ...mono, fontSize: 12, color: '#3a6a88' }}>Loading experiment…</div>
          ) : detail.error ? (
            <div role="alert" style={{ fontSize: 12, color: '#ffaa00' }}>{detail.error} <button type="button" style={btn} onClick={() => setReload((k) => k + 1)}>Retry</button></div>
          ) : detail.data ? (
            <ExperimentDetails experiment={detail.data.experiment} results={detail.data.results} canRun={canRun} onCancel={cancel} cancelling={cancelling} liveCaveat={meta?.liveCaveat || ''} />
          ) : null}
        </div>
      </div>

      <div style={{ marginTop: '1rem' }}><Observational data={obs} /></div>
    </DashboardLayout>
  )
}
