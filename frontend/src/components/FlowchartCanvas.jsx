import { useEffect, useRef, useState } from 'react';
import mermaid from 'mermaid';

const THEME_VARIABLES = {
  background: '#0d1117',
  mainBkg: '#161b22',
  secondaryBkg: '#1c2128',
  primaryColor: '#161b22',
  primaryTextColor: '#e6edf3',
  secondaryTextColor: '#e6edf3',
  tertiaryTextColor: '#8d96a0',
  labelTextColor: '#e6edf3',
  nodeBorder: '#444c56',
  clusterBkg: '#161b22',
  clusterBorder: '#2f3741',
  lineColor: '#8d96a0',
  fontSize: '13px',
  edgeLabelBackground: '#0d1117',
};

export default function FlowchartCanvas({ chart, kind }) {
  const [svgHtml, setSvgHtml] = useState('');
  const [error, setError] = useState(null);
  const idRef = useRef(`mermaid-${Math.random().toString(36).slice(2, 9)}`);

  const semanticLine = kind === 'threat' ? '#f85149'
    : kind === 'suspicious' ? '#d29922' : '#3fb950';
  const heading = kind === 'safe' ? 'Verification flow'
    : 'Attack chain';

  useEffect(() => {
    if (!chart) { setSvgHtml(''); return; }
    let cancelled = false;

    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'base',
      themeVariables: { ...THEME_VARIABLES, lineColor: semanticLine },
    });

    (async () => {
      try {
        const { svg } = await mermaid.render(idRef.current + '-tmp', chart);
        if (!cancelled) { setSvgHtml(svg); setError(null); }
      } catch (err) {
        if (!cancelled) {
          setError(err?.message || 'The flowchart could not be rendered');
          setSvgHtml('');
        }
      }
    })();

    return () => { cancelled = true; };
  }, [chart, kind, semanticLine]);

  return (
    <section className="rounded border border-line bg-surface p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-[15px] font-semibold text-ink">{heading}</h2>
        <span className="text-xs text-ink-dim">
          {kind === 'safe' ? 'How safety was verified' : 'Cyber Kill Chain'}
        </span>
      </div>

      {error ? (
        <div>
          <p className="mb-3 text-sm text-warn">Flowchart failed to render: {error}</p>
          <pre className="max-h-72 overflow-auto rounded border border-line bg-canvas p-4 text-xs text-ink-dim">
            {chart}
          </pre>
        </div>
      ) : svgHtml ? (
        <div
          className="flex justify-center overflow-auto rounded border border-line bg-canvas p-6"
          dangerouslySetInnerHTML={{ __html: svgHtml }}
        />
      ) : (
        <div className="flex h-32 items-center justify-center text-sm text-ink-dim" aria-live="polite">
          Rendering flowchart…
        </div>
      )}
    </section>
  );
}
