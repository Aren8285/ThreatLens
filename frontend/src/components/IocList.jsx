const TYPE_STYLE = {
  url: 'border-line text-ink-dim',
  domain: 'border-line text-ink-dim',
  ipv4: 'border-line text-ink-dim',
  email: 'border-line text-ink-dim',
  crypto_wallet: 'border-line text-ink-dim',
};

const OVERALL_STYLE = {
  malicious: 'bg-danger-tint text-danger border-danger',
  suspicious: 'bg-warn-tint text-warn border-warn',
  mixed: 'border-warn text-warn',
  clean: 'text-good border-good',
  lookup_failed: 'border-line text-ink-faint',
  not_configured: 'border-line text-ink-faint',
  not_queryable: 'border-line text-ink-faint',
};

const TYPE_LABEL = {
  url: 'URL',
  domain: 'Domain',
  ipv4: 'IP address',
  email: 'Email',
  crypto_wallet: 'Wallet',
};

export default function IocList({ iocs = [], osintRecords = [] }) {
  const osintByRaw = new Map(osintRecords.map((r) => [r.raw, r]));
  return (
    <section className="rounded border border-line bg-surface p-5">
      <h2 className="mb-4 text-[15px] font-semibold text-ink">
        Indicators extracted <span className="font-normal text-ink-dim">({iocs.length})</span>
      </h2>
      {iocs.length === 0 ? (
        <p className="text-sm text-ink-dim">
          No URLs, domains, addresses, or wallets were found in the message.
        </p>
      ) : (
        <ul className="space-y-2 list-none">
          {iocs.map((ioc, i) => {
            const o = osintByRaw.get(ioc.raw);
            const overall = o?.overall;
            return (
              <li key={i} className="reveal rounded border border-line bg-raised p-3 min-w-0">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 min-w-0">
                  <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium ${TYPE_STYLE[ioc.ioc_type]}`}>
                    {TYPE_LABEL[ioc.ioc_type] || ioc.ioc_type}
                  </span>
                  <code className="break-all font-mono text-sm text-ink">{ioc.defanged}</code>
                  {overall && (
                    <span className={`ml-auto shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium ${OVERALL_STYLE[overall] || OVERALL_STYLE.not_queryable}`}>
                      {overall.replaceAll('_', ' ')}
                    </span>
                  )}
                </div>
                {(ioc.notes || []).length > 0 && (
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-dim">
                    {ioc.notes.join(' · ')}
                  </p>
                )}
                {o && (o.lookups || []).some((l) => l?.engine_verdicts_sample?.length) && (
                  <p className="mt-1.5 break-words text-xs text-ink-faint">
                    {'Engines: '}
                    {o.lookups.flatMap((l) => l.engine_verdicts_sample || []).slice(0, 5).join(' · ')}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <p className="mt-3 text-xs text-ink-faint">
        Indicators are shown defanged (hXXp, [.]) so they cannot be clicked or accidentally opened.
      </p>
    </section>
  );
}
