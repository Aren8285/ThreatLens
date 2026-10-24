import { Skull, ShieldCheck, AlertTriangle } from 'lucide-react';

const KIND = {
  threat: {
    border: 'border-danger',
    bg: 'bg-danger-tint',
    text: 'text-danger',
    icon: Skull,
    sub: 'Malicious indicators detected in this message.',
  },
  suspicious: {
    border: 'border-warn',
    bg: 'bg-warn-tint',
    text: 'text-warn',
    icon: AlertTriangle,
    sub: 'Mixed evidence — treat this message with caution.',
  },
  safe: {
    border: 'border-good',
    bg: 'bg-good-tint',
    text: 'text-good',
    icon: ShieldCheck,
    sub: 'Consistent with a legitimate message or false positive.',
  },
};

export default function VerdictBanner({ report, kind }) {
  const k = KIND[kind] || KIND.suspicious;
  const Icon = k.icon;
  return (
    <section
      aria-live="polite"
      className={`reveal rounded border ${k.border} ${k.bg} p-6`}
    >
      <div className="flex flex-wrap items-center gap-5">
        <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-full border-2 ${k.border} ${k.text}`}>
          <Icon aria-hidden="true" className="h-7 w-7" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium text-ink-dim">Final verdict</p>
          <h2 className={`text-2xl font-bold leading-snug text-pretty ${k.text}`}>
            {report.verdict}
          </h2>
          <p className="mt-1 text-sm text-ink-dim">{k.sub}</p>
        </div>
        <div className="text-right">
          <p className="text-xs font-medium text-ink-dim">Confidence</p>
          <p className={`text-4xl font-bold tabular ${k.text}`}>
            {report.confidence_score}
          </p>
          <p className="text-xs text-ink-faint tabular">out of 100</p>
        </div>
      </div>
    </section>
  );
}
