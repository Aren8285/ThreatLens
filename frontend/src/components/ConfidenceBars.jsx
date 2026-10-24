function Bar({ label, pct, color }) {
  const clamped = Math.max(0, Math.min(100, pct ?? 0));
  const fill = color === 'red' ? 'bg-danger' : color === 'amber' ? 'bg-warn'
    : color === 'green' ? 'bg-good' : 'bg-accent';
  const text = color === 'red' ? 'text-danger' : color === 'amber' ? 'text-warn'
    : color === 'green' ? 'text-good' : 'text-accent';
  return (
    <div className="min-w-0">
      <div className="mb-1.5 flex items-baseline justify-between gap-2">
        <span className="text-xs text-ink-dim">{label}</span>
        <span className={`text-sm font-semibold tabular ${pct == null ? 'text-ink-faint' : text}`}>
          {pct == null ? '—' : `${Math.round(clamped)}%`}
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-raised" role="img" aria-label={pct == null ? `${label}: no data` : `${label}: ${clamped}%`}>
        <div
          className={`h-full rounded-full ${fill}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
}

export default function ConfidenceBars({ report }) {
  const ml = report.ml_triage || {};
  const p = ml.phishing_probability;

  let osintPct = null;
  for (const rec of report.osint_records || []) {
    for (const l of rec.lookups || []) {
      if (l.provider === 'virustotal' && l.detections) {
        const d = l.detections;
        const total = (d.malicious || 0) + (d.suspicious || 0) + (d.harmless || 0);
        if (total > 0) {
          const bad = ((d.malicious || 0) + 0.5 * (d.suspicious || 0)) / total * 100;
          osintPct = Math.max(osintPct ?? 0, bad);
        }
      }
    }
  }

  return (
    <section className="rounded border border-line bg-surface p-5">
      <h2 className="mb-5 text-[15px] font-semibold text-ink">Evidence scores</h2>
      <div className="grid gap-5 md:grid-cols-3">
        <Bar
          label="Overall confidence"
          pct={report.confidence_score}
          color={report.verdict === 'High Risk Threat' ? 'red'
            : report.verdict === 'Suspicious' ? 'amber' : 'green'}
        />
        <Bar label={ml.engine ? `ML classifier · ${ml.engine}` : 'ML classifier'}
             pct={p == null ? null : p * 100} color="blue-command" />
        <Bar label="Reputation verdicts flagging malicious" pct={osintPct} color="red" />
      </div>
      {ml.model && (
        <p className="mt-4 break-words text-xs text-ink-faint">
          Classifier model: <span className="font-mono text-ink-dim">{ml.model}</span>
        </p>
      )}
    </section>
  );
}
