import { useState } from 'react'
import { Link } from 'react-router-dom'
import Panel from '../Panel.jsx'
import SeverityBadge from '../SeverityBadge.jsx'
import ExplanationModal from '../ExplanationModal.jsx'
import TrustBadge from './TrustBadge.jsx'
import { REASON_KIND, STATE_META, MODEL_LIMITATIONS, anomalySummary, inputSummary, pct } from '../../utils/trustMeter.js'
import { dateText, timeText, REPORT_TIME_ZONE } from '../../utils/reportingTime.js'

const mono = { fontFamily: 'Share Tech Mono,monospace' }
const sub = { ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1 }
export const btn = {
  background: 'transparent', border: '1px solid #1a4a6e', color: '#7ab3cc', borderRadius: 2,
  fontFamily: 'Rajdhani,sans-serif', fontWeight: 700, fontSize: 12, letterSpacing: 1,
  padding: '7px 12px', cursor: 'pointer', textTransform: 'uppercase', textDecoration: 'none', display: 'inline-block',
}

function Bar({ value, color, label }) {
  const ok = typeof value === 'number' && Number.isFinite(value)
  return (
    <div>
      <div role="img" aria-label={`${label}: ${ok ? pct(value) : 'unavailable'}`} style={{ height: 6, background: '#0d3352', borderRadius: 1, overflow: 'hidden' }}>
        {ok && <div style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%`, height: '100%', background: color }} />}
      </div>
    </div>
  )
}

function Metric({ label, value, note, testId, children }) {
  return (
    <div data-testid={testId} style={{ background: 'rgba(2,11,24,.5)', border: '1px solid #0d3352', padding: '0.8rem', minWidth: 0 }}>
      <div style={sub}>{label}</div>
      <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, color: '#c8e6f5', margin: '6px 0', overflowWrap: 'anywhere' }}>{value}</div>
      {children}
      {note && <div style={{ fontSize: 12, color: '#7ab3cc', marginTop: 6, lineHeight: 1.4 }}>{note}</div>}
    </div>
  )
}

function Reason({ r, open }) {
  const kind = REASON_KIND[r.kind] || REASON_KIND.info
  return (
    <details open={open} data-testid="trust-reason" data-code={r.code} style={{ border: '1px solid #0d3352', borderLeft: `3px solid ${kind.color}`, padding: '8px 10px', background: 'rgba(2,11,24,.4)' }}>
      <summary style={{ cursor: 'pointer', display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
        <span style={{ ...mono, fontSize: 9, color: kind.color, border: `1px solid ${kind.color}55`, padding: '1px 5px' }}>{kind.label}</span>
        <span style={{ fontWeight: 600, fontSize: 14 }}>{r.title}</span>
      </summary>
      <div style={{ marginTop: 8, fontSize: 13, lineHeight: 1.5, color: '#c8e6f5' }}>{r.description}</div>
      <dl style={{ margin: '8px 0 0', display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '4px 10px', fontSize: 12 }}>
        {r.value !== null && r.value !== undefined && (<><dt style={sub}>VALUE</dt><dd style={{ margin: 0, ...mono, overflowWrap: 'anywhere' }}>{String(r.value)}</dd></>)}
        <dt style={sub}>SOURCE FIELD</dt><dd style={{ margin: 0, ...mono }}>{r.source}</dd>
        <dt style={sub}>HOW TO READ IT</dt><dd style={{ margin: 0 }}>{r.interpretation}</dd>
      </dl>
    </details>
  )
}

export function ModelLimitations() {
  return (
    <Panel title="Known model limitations" badge="DATASET-LEVEL" badgeType="warn">
      <div data-testid="trust-limitations">
        <p style={{ margin: '0 0 10px', fontSize: 14, lineHeight: 1.5 }}>
          Deployed classifier <code style={mono}>{MODEL_LIMITATIONS.model}</code>, trained on {MODEL_LIMITATIONS.trainedOn} These are three separate evaluations and are not directly comparable.
        </p>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 8 }}>
          {MODEL_LIMITATIONS.evaluations.map((e) => (
            <li key={e.id} style={{ border: '1px solid #0d3352', padding: '8px 10px' }}>
              <div style={{ fontWeight: 600, fontSize: 14 }}>{e.title}</div>
              <div style={{ ...mono, fontSize: 12, color: '#00d4ff', margin: '4px 0' }}>{e.result}</div>
              <div style={{ fontSize: 12, color: '#7ab3cc' }}>{e.caveat}</div>
              <div style={{ ...sub, marginTop: 4 }}>SOURCE: {e.source}</div>
            </li>
          ))}
        </ul>
        <p style={{ margin: '10px 0 0', fontSize: 13, color: '#ffaa00', lineHeight: 1.5 }}>{MODEL_LIMITATIONS.takeaway}</p>
        <p style={{ margin: '6px 0 0', fontSize: 12, color: '#7ab3cc' }}>
          No validated per-prediction out-of-distribution or calibration measure exists in SentinelAI, so none is shown. The Isolation Forest signal is not used as one.
        </p>
      </div>
    </Panel>
  )
}

export default function TrustDetails({ prediction, onBack }) {
  const [explain, setExplain] = useState(false)
  const t = prediction.trust
  const meta = STATE_META[t.state] || STATE_META.INSUFFICIENT
  const limiting = t.reasons.filter((r) => r.kind !== 'info')
  const context = t.reasons.filter((r) => r.kind === 'info')
  const created = Date.parse(prediction.createdAt)
  const other = t.classifier.topClasses.filter((c) => c.label !== t.classifier.predictedClass)

  return (
    <div data-testid="trust-details">
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', marginBottom: '1rem' }}>
        <button type="button" style={btn} onClick={onBack} data-testid="trust-back">← Prediction history</button>
        <span style={{ ...mono, fontSize: 11, color: '#3a6a88' }}>PREDICTION {prediction._id}</span>
      </div>

      <Panel style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={sub}>SENTINELAI PREDICTED</div>
            <div data-testid="trust-class" style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 22, color: '#c8e6f5' }}>{t.classifier.predictedClass || 'Unavailable'}</div>
            <div style={{ ...mono, fontSize: 11, color: '#7ab3cc', marginTop: 4 }}>
              {Number.isFinite(created) ? `${dateText(created)} ${timeText(created)} (${REPORT_TIME_ZONE})` : 'Time not recorded'} · source {prediction.sourceIP || 'not recorded'} · model {t.modelVersion.value || 'not recorded'}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <TrustBadge state={t.state} large />
            <div data-testid="trust-state-description" style={{ fontSize: 13, color: '#c8e6f5', maxWidth: 420, marginTop: 6 }}>{meta.description}</div>
          </div>
        </div>
      </Panel>

      <div className="trust-metrics" style={{ marginBottom: '1rem' }}>
        <Metric testId="trust-confidence" label="CLASSIFIER CONFIDENCE (XGBOOST)" value={pct(t.classifier.confidence)} note={t.classifier.status === 'available' ? t.classifier.note : 'No stored probability for the predicted class.'}>
          <Bar value={t.classifier.confidence} color="#00d4ff" label="Classifier confidence" />
          {other.length > 0 && (
            <div style={{ ...mono, fontSize: 11, color: '#7ab3cc', marginTop: 6 }}>
              Next: {other.map((c) => `${c.label} ${pct(c.probability)}`).join(' · ')}
            </div>
          )}
        </Metric>
        <Metric testId="trust-threat-score" label="THREAT SCORE" value={pct(t.threatScore)} note="SentinelAI’s combined score that the alert and block lines use. It is not the classifier’s confidence.">
          <Bar value={t.threatScore} color="#8b5cf6" label="Threat score" />
        </Metric>
        <Metric testId="trust-anomaly" label="ANOMALY SIGNAL (ISOLATION FOREST)" value={anomalySummary(t.anomaly)} note={t.anomaly.note || 'No anomaly signal can be interpreted for this prediction.'} />
        <Metric testId="trust-input" label="INPUT QUALITY" value={t.input.status === 'complete' ? 'Complete' : t.input.status === 'incomplete' ? 'Incomplete' : 'Not verifiable'} note={inputSummary(t.input)}>
          {t.input.defaultedFeatures.length > 0 && (
            <div data-testid="trust-defaulted" style={{ ...mono, fontSize: 11, color: '#f5c542', overflowWrap: 'anywhere' }}>
              Missing: {t.input.defaultedFeatures.join(', ')}
            </div>
          )}
        </Metric>
      </div>

      <div className="dashboard-grid dashboard-grid-two" style={{ gap: '1rem', alignItems: 'start', marginBottom: '1rem' }}>
        <Panel title="Why this assessment" badge={`${limiting.length} FINDING${limiting.length === 1 ? '' : 'S'}`} badgeType={limiting.length ? 'warn' : 'ok'}>
          {limiting.length === 0 ? (
            <div data-testid="trust-no-findings" style={{ fontSize: 13, color: '#c8e6f5' }}>
              No limiting factor was found by the available checks. This does not establish that the prediction is correct.
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 8 }}>{limiting.map((r, i) => <Reason key={r.code} r={r} open={i === 0} />)}</div>
          )}
          {context.length > 0 && (
            <>
              <div style={{ ...sub, margin: '12px 0 6px' }}>CONTEXT (DOES NOT CHANGE THE ASSESSMENT)</div>
              <div style={{ display: 'grid', gap: 8 }}>{context.map((r) => <Reason key={r.code} r={r} />)}</div>
            </>
          )}
        </Panel>

        <div style={{ display: 'grid', gap: '1rem', minWidth: 0 }}>
          <Panel title="Model signals side by side">
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <caption style={{ position: 'absolute', left: -9999 }}>Classifier and anomaly detector outputs</caption>
              <thead><tr style={{ ...sub, textAlign: 'left' }}><th scope="col" style={{ padding: 4 }}>MODEL</th><th scope="col" style={{ padding: 4 }}>OUTPUT</th><th scope="col" style={{ padding: 4 }}>WHAT IT IS</th></tr></thead>
              <tbody>
                <tr style={{ borderTop: '1px solid #0d3352' }}>
                  <td style={{ padding: 6 }}>XGBoost classifier</td>
                  <td style={{ padding: 6, ...mono }}>{t.classifier.predictedClass} · {pct(t.classifier.confidence)}</td>
                  <td style={{ padding: 6, color: '#7ab3cc' }}>Class label and the model output for it</td>
                </tr>
                <tr style={{ borderTop: '1px solid #0d3352' }}>
                  <td style={{ padding: 6 }}>Isolation Forest</td>
                  <td style={{ padding: 6, ...mono }}>{anomalySummary(t.anomaly)}</td>
                  <td style={{ padding: 6, color: '#7ab3cc' }}>Unusualness against its configured boundary; not an attack probability</td>
                </tr>
              </tbody>
            </table>
            <div style={{ fontSize: 12, color: '#7ab3cc', marginTop: 8 }}>
              {t.anomaly.status !== 'available'
                ? 'Agreement between the two models cannot be evaluated for this prediction.'
                : 'How the signals relate is listed under “Why this assessment”. Agreement never proves correctness.'}
            </div>
          </Panel>

          <Panel title="Linked records">
            {prediction.threat ? (
              <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
                <div>
                  Threat record <span style={mono}>{prediction.threat._id}</span> · {prediction.threat.attackType} · <SeverityBadge sev={prediction.threat.severity} /> · {prediction.threat.status}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  <Link to="/dashboard/threats" style={btn}>Open Threat Logs</Link>
                  {prediction.explanation?.available ? (
                    <button type="button" data-testid="trust-open-shap" style={{ ...btn, color: '#b49cff', borderColor: 'rgba(139,92,246,.5)' }} onClick={() => setExplain(true)}>
                      Open SHAP explanation
                    </button>
                  ) : (
                    <span data-testid="trust-shap-unavailable" style={{ fontSize: 12, color: '#7ab3cc', alignSelf: 'center' }}>
                      {prediction.explanation?.requiresRole
                        ? 'SHAP explanations are available to analyst and admin roles.'
                        : 'No stored feature vector, so no SHAP explanation can be produced.'}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: '#7ab3cc' }}>
                  SHAP shows which input features pushed the classifier toward its answer. The Trust Meter shows what limits how far that answer can be relied on.
                </div>
              </div>
            ) : (
              <div style={{ fontSize: 13, color: '#7ab3cc' }}>
                No threat record was raised from this prediction. SHAP explanations are served per threat record, so none is linked here.
              </div>
            )}
          </Panel>
        </div>
      </div>

      <ModelLimitations />
      {explain && prediction.threat && (
        <ExplanationModal key={prediction.threat._id} isOpen threat={prediction.threat} onClose={() => setExplain(false)} />
      )}
    </div>
  )
}
