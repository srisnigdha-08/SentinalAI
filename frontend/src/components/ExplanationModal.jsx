import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ReferenceLine, ResponsiveContainer, Cell } from 'recharts'
import Modal from './Modal.jsx'
import { threatAPI } from '../services/api.js'
import { contributionRows, explanationError, explanationSummary, formatPercent } from '../utils/threatExplanation.js'

const mono = { fontFamily: 'Share Tech Mono,monospace' }
const TOWARD = '#ff2d55'
const AWAY = '#00d4ff'

function Field({ label, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 11, ...mono }}>
      <span style={{ color: '#3a6a88' }}>{label}</span>
      <span style={{ color: '#c8e6f5', textAlign: 'right' }}>{children}</span>
    </div>
  )
}

/**
 * On-demand SHAP explanation of one threat (XAI-001). The backend explains the feature vector stored with the
 * threat's own prediction and only answers when re-scoring reproduces that prediction, so nothing here is guessed.
 * The parent mounts it per threat (`key`), so state never leaks between threats.
 */
export default function ExplanationModal({ isOpen, threat, onClose }) {
  const [state, setState] = useState({ loading: true, data: null, error: null })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (!isOpen || !threat?._id) return undefined
    let active = true // ignore a response that arrives after the modal closed or the request was retried
    setState({ loading: true, data: null, error: null })
    threatAPI
      .explain(threat._id)
      .then(r => { if (active) setState({ loading: false, data: r.data?.data || null, error: null }) })
      .catch(err => { if (active) setState({ loading: false, data: null, error: explanationError(err) }) })
    return () => { active = false }
  }, [isOpen, threat?._id, attempt])

  if (!isOpen || !threat) return null
  const { loading, data, error } = state
  const { rows, restCount, restSum } = contributionRows(data?.contributions, 10)
  const chartRows = [...rows].reverse() // largest at the top of a vertical bar chart

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Model Explanation" subtitle="// SHAP contributions for this prediction" maxWidth="720px">
      {loading && <div style={{ ...mono, fontSize: 12, color: '#7ab3cc', padding: '1rem 0' }}>Computing explanation…</div>}

      {error && (
        <div role="alert" data-testid="explanation-error" style={{ ...mono, fontSize: 12, color: '#ffaa00', padding: '0.75rem 0', lineHeight: 1.6 }}>
          {error.message}
          {error.retryable && (
            <div style={{ marginTop: 8 }}>
              <button type="button" onClick={() => setAttempt(a => a + 1)}
                style={{ background: 'transparent', border: '1px solid #00d4ff', color: '#00d4ff', padding: '3px 10px', fontSize: 10, cursor: 'pointer', ...mono }}>
                TRY AGAIN
              </button>
            </div>
          )}
        </div>
      )}

      {data && (
        <div data-testid="explanation" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ background: '#041120', border: '1px solid #0d3352', padding: '10px 12px', display: 'grid', gap: 6 }}>
            <Field label="Predicted class">{data.predictedClass}</Field>
            {data.explainedClass && data.explainedClass !== data.predictedClass && (
              <Field label="Classifier class (explained)">{data.explainedClass}</Field>
            )}
            <Field label="Model confidence">{formatPercent(data.confidence)}</Field>
            <Field label="Threat score">{Number(data.threatScore).toFixed(4)}</Field>
            <Field label="Model version">{data.modelVersion}</Field>
            <Field label="Predicted at">{data.predictedAt ? new Date(data.predictedAt).toLocaleString() : '—'}</Field>
            <Field label="Source">reproduced from the features stored with this prediction</Field>
          </div>

          <p style={{ fontSize: 12, color: '#c8e6f5', margin: 0, lineHeight: 1.6 }}>{explanationSummary(data)}</p>

          <div style={{ width: '100%', height: Math.max(220, chartRows.length * 26 + 40) }}>
            <ResponsiveContainer>
              <BarChart data={chartRows} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
                <XAxis type="number" tick={{ fill: '#7ab3cc', fontSize: 10 }} />
                <YAxis type="category" dataKey="feature" width={190} tick={{ fill: '#c8e6f5', fontSize: 10 }} />
                <ReferenceLine x={0} stroke="#3a6a88" />
                <Tooltip
                  contentStyle={{ background: '#081f35', border: '1px solid #0d3352', fontSize: 11 }}
                  formatter={(v, _n, item) => [`${v} (value ${item?.payload?.value ?? '—'})`, 'contribution']}
                />
                <Bar dataKey="contribution" isAnimationActive={false}>
                  {chartRows.map(r => <Cell key={r.feature} fill={r.direction === 'toward' ? TOWARD : AWAY} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          {restCount > 0 && (
            <div style={{ ...mono, fontSize: 10, color: '#3a6a88' }}>
              The other {restCount} features together contribute {restSum}.
            </div>
          )}

          <div style={{ fontSize: 11, color: '#7ab3cc', lineHeight: 1.6, borderTop: '1px solid #0d3352', paddingTop: 10 }}>
            <strong style={{ color: '#c8e6f5' }}>How to read this.</strong>{' '}
            <span style={{ color: TOWARD }}>Red bars</span> push the classifier towards the class it chose,{' '}
            <span style={{ color: AWAY }}>blue bars</span> push it away; longer means stronger. Values are SHAP
            contributions in the classifier's internal log-odds units, so compare them with each other rather than read
            them as percentages. They explain the XGBoost classifier only: the threat score also includes the
            Isolation Forest anomaly signal, which is not broken down here. A contribution shows what influenced this
            model, not what caused the attack.
          </div>
        </div>
      )}
    </Modal>
  )
}
