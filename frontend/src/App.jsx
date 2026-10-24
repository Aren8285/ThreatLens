import { useEffect, useState, useRef } from 'react';
import {
  ShieldAlert, Loader2, AlertTriangle, FileWarning, Info,
  Brain, Globe, Wrench, Gauge, Camera,
} from 'lucide-react';
import { analyze, health, fileToDataUri } from './api.js';
import InputPanel from './components/InputPanel.jsx';
import VerdictBanner from './components/VerdictBanner.jsx';
import ConfidenceBars from './components/ConfidenceBars.jsx';
import Card from './components/Card.jsx';
import IocList from './components/IocList.jsx';
import FlowchartCanvas from './components/FlowchartCanvas.jsx';

function App() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const resultsRef = useRef(null);

  useEffect(() => {
    health().then(setStatus).catch(() => setStatus(null));
  }, []);

  const run = async ({ text, imageFile }) => {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const payload = {};
      if (text) payload.text = text;
      if (imageFile) payload.image_base64 = await fileToDataUri(imageFile);
      const data = await analyze(payload);
      setReport(data);
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80);
    } catch (err) {
      setError(err.message || 'Analysis failed — check that the backend is running on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  const verdictKind = report
    ? (report.verdict === 'High Risk Threat' ? 'threat'
       : report.verdict === 'Suspicious' ? 'suspicious' : 'safe')
    : 'idle';

  return (
    <div className="relative min-h-screen">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-6 py-4">
          <div className="flex h-10 w-10 items-center justify-center rounded bg-accent-tint">
            <ShieldAlert aria-hidden="true" className="h-5 w-5 text-accent" />
          </div>
          <div className="min-w-0 flex-1">
            <h1 className="text-lg font-semibold tracking-tight text-ink">ThreatLens</h1>
            <p className="text-xs text-ink-dim">
              Phishing and threat-intelligence triage — indicators, reputation, and a final verdict
            </p>
          </div>
          <StatusPill status={status} />
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-6 py-8">
        <InputPanel onRun={run} loading={loading} />

        {error && (
          <div role="alert" className="flex items-start gap-3 rounded border border-danger bg-danger-tint p-4" aria-live="assertive">
            <AlertTriangle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <p className="text-sm text-ink">{error}</p>
          </div>
        )}

        {loading && (
          <div className="flex items-center justify-center gap-3 rounded border border-line bg-surface px-8 py-10" aria-live="polite">
            <Loader2 aria-hidden="true" className="h-5 w-5 animate-spin text-accent" />
            <div className="min-w-0">
              <p className="text-sm font-medium text-ink">Analyzing the message…</p>
              <p className="mt-0.5 text-xs text-ink-dim">
                Reputation lookups take up to a minute when a URL has no prior record.
              </p>
            </div>
          </div>
        )}

        {report && (
          <section ref={resultsRef} className="space-y-6 scroll-mt-4">
            {report.degraded && (
              <div className="flex items-start gap-3 rounded border border-warn bg-warn-tint p-4">
                <FileWarning aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-ink">
                    Report generated from rules only — no LLM synthesis
                  </p>
                  <p className="mt-1 text-xs text-ink-dim">{report.degradation_reason}</p>
                </div>
              </div>
            )}

            <VerdictBanner report={report} kind={verdictKind} />
            <FlowchartCanvas chart={report.attack_flowchart} kind={verdictKind} />

            <div className="grid gap-6 lg:grid-cols-2">
              <Card title="Psychological Analysis" icon={Brain}>
                {report.psychological_analysis?.summary && (
                  <p className="mb-4 text-sm leading-relaxed text-ink">
                    {report.psychological_analysis.summary}
                  </p>
                )}
                <div className="space-y-2">
                  {(report.psychological_analysis?.tactics || []).map((t, i) => (
                    <div key={i} className="rounded border border-line bg-raised p-3 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-medium text-ink">{t.name}</span>
                        <SeverityBadge severity={t.severity} />
                      </div>
                      {t.evidence && (
                        <p className="mt-1 break-words text-xs text-ink-dim">“{t.evidence}”</p>
                      )}
                    </div>
                  ))}
                  {!report.psychological_analysis?.tactics?.length && (
                    <p className="text-sm text-ink-dim">No manipulation tactics were found.</p>
                  )}
                </div>
              </Card>

              <Card title="Reputation Findings" icon={Globe}>
                <p className="whitespace-pre-line text-sm leading-relaxed text-ink">
                  {report.osint_findings || 'No reputation data was collected.'}
                </p>
              </Card>

              <Card title="Remediation Steps" icon={Wrench}>
                <ol className="space-y-2 list-decimal">
                  {(report.remediation_steps || []).map((step, i) => (
                    <li key={i} className="rounded border border-warn bg-warn-tint px-3 py-2 text-sm text-ink marker:font-semibold marker:text-warn">
                      {step}
                    </li>
                  ))}
                </ol>
              </Card>

              <Card title="Classifiers and Evidence" icon={Gauge}>
                <EvidencePanel report={report} />
              </Card>
            </div>

            <IocList iocs={report.iocs} osintRecords={report.osint_records} />

            {report.ocr_text && (
              <Card title="Extracted Source (OCR)" icon={Camera}>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded border border-line bg-canvas p-4 font-mono text-xs leading-relaxed text-ink-dim">
                  {report.ocr_text}
                </pre>
              </Card>
            )}

            <details className="rounded border border-line bg-surface">
              <summary className="cursor-pointer px-4 py-3 text-sm text-ink-dim transition-colors hover:text-ink">
                Raw JSON report
              </summary>
              <pre className="max-h-96 overflow-auto border-t border-line p-4 text-xs text-ink-dim">
                {JSON.stringify(report, null, 2)}
              </pre>
            </details>
          </section>
        )}

        {!report && !loading && !error && (
          <div className="flex items-center justify-center gap-2 text-sm text-ink-dim">
            <Info aria-hidden="true" className="h-4 w-4" />
            Paste a suspicious message or attach a screenshot to begin.
          </div>
        )}
      </main>

      <footer className="border-t border-line py-5 text-center text-xs text-ink-faint">
        ThreatLens provides analysis support — confirm high-confidence verdicts before acting.
      </footer>
    </div>
  );
}

function StatusPill({ status }) {
  const capabilities = status?.capabilities || {};
  const items = [
    ['LLM', capabilities.llm_synthesis],
    ['Vision', capabilities.vision_ocr],
    ['ML', capabilities.local_ml_model],
    ['Intel', capabilities.osint],
  ];
  return (
    <div className="flex items-center gap-2 text-xs text-ink-dim" aria-label="Available services">
      {items.map(([label, value]) => (
        <span key={label} className="flex items-center gap-1.5 px-1">
          <span
            aria-hidden="true"
            className={`h-1.5 w-1.5 rounded-full ${value ? 'bg-good' : 'bg-line-strong'}`}
          />
          {label}
        </span>
      ))}
      {!status && <span className="text-danger">Backend offline</span>}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const map = {
    critical: 'bg-danger-tint text-danger border-danger',
    high: 'text-danger border-danger',
    medium: 'text-warn border-warn',
    low: 'text-ink-faint border-line',
    none: 'text-ink-faint border-line',
  };
  return (
    <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium ${map[severity] || map.low}`}>
      {severity}
    </span>
  );
}

function EvidencePanel({ report }) {
  const ml = report.ml_triage || {};
  const p = ml.phishing_probability;
  return (
    <div className="space-y-2 text-sm">
      <div className="flex items-center justify-between gap-2 rounded border border-line bg-raised px-3 py-2 min-w-0">
        <span className="min-w-0 truncate text-ink-dim">NLP classifier</span>
        <span className={`shrink-0 tabular ${p == null ? 'text-ink-faint'
          : p >= 0.5 ? 'text-danger' : 'text-good'}`}>
          {p == null ? 'unavailable'
            : `${(p * 100).toFixed(1)}% phishing`}
        </span>
      </div>
      {(report.osint_records || []).map((rec, i) => (
        <div key={i} className="flex items-center justify-between gap-2 rounded border border-line bg-raised px-3 py-2 min-w-0">
          <code className="min-w-0 truncate font-mono text-xs text-ink">{rec.defanged}</code>
          <span className={`shrink-0 text-xs ${rec.overall === 'malicious' ? 'text-danger'
            : rec.overall === 'suspicious' || rec.overall === 'mixed' ? 'text-warn'
            : rec.overall === 'clean' ? 'text-good' : 'text-ink-faint'}`}>
            {rec.overall.replaceAll('_', ' ')}
          </span>
        </div>
      ))}
    </div>
  );
}

export default App;
