import { useState, useRef, useCallback } from 'react';
import { Upload as UploadIcon, Sparkles as SparklesIcon, X as XIcon, ArrowRight, ImageUp, FileText, Loader2 } from 'lucide-react';

export default function InputPanel({ onRun, loading }) {
  const [tab, setTab] = useState('text'); // 'text' | 'image'
  const [text, setText] = useState('');
  const [image, setImage] = useState(null); // {file, previewUrl}
  const [dragOver, setDragOver] = useState(false);
  const [validationError, setValidationError] = useState(null);
  const inputRef = useRef(null);
  const textareaRef = useRef(null);

  const handleFile = useCallback((file) => {
    setValidationError(null);
    if (!file || !file.type.startsWith('image/')) {
      setValidationError('That file is not an image. Choose a PNG, JPG, or WebP screenshot.');
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setValidationError('The screenshot is over 8 MB. Compress or resize it, then try again.');
      return;
    }
    // api.js enforces the same limit on read
    const previewUrl = URL.createObjectURL(file);
    const reader = new FileReader();
    reader.onload = () => {
      setImage({ file, previewUrl });
      setTab('image');
    };
    reader.readAsDataURL(file);
  }, []);

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    handleFile(e.dataTransfer.files?.[0]);
  };

  const submit = () => {
    if (loading) return;
    if (tab === 'text' && !text.trim()) {
      setValidationError('Enter a message to analyze, or switch to the screenshot tab.');
      textareaRef.current?.focus();
      return;
    }
    if (tab === 'image' && !image) {
      setValidationError('Add a screenshot first — click the drop zone to browse, or drag one in.');
      inputRef.current?.focus();
      return;
    }
    setValidationError(null);
    onRun({ text: tab === 'text' ? text : undefined, imageFile: tab === 'image' ? image.file : undefined });
  };

  return (
    <section className="rounded border border-line bg-surface">
      <div className="flex items-center gap-1 border-b border-line px-3 pt-2" role="tablist" aria-label="Input type">
        {[
          ['text', 'Paste text', FileText],
          ['image', 'Screenshot', ImageUp],
        ].map(([id, label, Icon]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              tab === id
                ? 'border-accent text-ink'
                : 'border-transparent text-ink-dim hover:text-ink'}`}
          >
            <Icon aria-hidden="true" className="h-4 w-4" />
            {label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => onRun({ text: DEMO_TEXT })}
          disabled={loading}
          className="ml-auto mb-1.5 flex items-center gap-1.5 rounded border border-line px-3 py-1.5 text-xs font-medium text-ink-dim transition-colors hover:border-line-strong hover:text-ink disabled:opacity-40"
        >
          <SparklesIcon aria-hidden="true" className="h-3.5 w-3.5" />
          Load example message
        </button>
      </div>

      <div className="p-4">
        {tab === 'text' && (
          <label htmlFor="message-input" className="block">
            <span className="mb-1.5 block text-xs font-medium text-ink-dim">Suspicious message</span>
            <textarea
              id="message-input"
              ref={textareaRef}
              value={text}
              onChange={(e) => { setText(e.target.value); setValidationError(null); }}
              onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) submit(); }}
              rows={9}
              spellCheck={false}
              autoComplete="off"
              placeholder="Paste the email body, SMS, chat message…"
              className="w-full resize-y rounded border border-line bg-canvas p-3 font-mono text-sm leading-relaxed text-ink transition-colors placeholder:text-ink-faint focus:border-line-strong"
            />
          </label>
        )}

        {tab === 'image' && (
          image ? (
            <div className="relative rounded border border-line bg-raised p-4">
              <img src={image.previewUrl} alt="Screenshot preview before analysis" width="560" height="200" className="mx-auto max-h-72 rounded" />
              <button
                type="button"
                aria-label="Remove screenshot"
                onClick={() => setImage(null)}
                className="absolute right-2 top-2 flex items-center rounded border border-line bg-surface px-2 py-1 text-xs text-ink-dim transition-colors hover:text-ink"
              >
                <XIcon aria-hidden="true" className="mr-1 h-3 w-3" /> Remove
              </button>
            </div>
          ) : (
            <button
              type="button"
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              onClick={() => inputRef.current?.click()}
              className={`flex w-full flex-col items-center justify-center gap-3 rounded border border-dashed px-8 py-12 text-center transition-colors ${
                dragOver
                  ? 'border-accent bg-accent-tint'
                  : 'border-line hover:border-line-strong hover:bg-raised'}`}
            >
              <UploadIcon aria-hidden="true" className={`h-8 w-8 ${dragOver ? 'text-accent' : 'text-ink-faint'}`} />
              <span className="block text-sm font-medium text-ink">
                {dragOver ? 'Release to attach' : 'Drop a screenshot here, or click to browse'}
              </span>
              <span className="block text-xs text-ink-dim">
                PNG, JPG, or WebP up to 8 MB — text is extracted automatically
              </span>
            </button>
          )
        )}
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          className="sr-only"
          tabIndex={-1}
          onChange={(e) => handleFile(e.target.files?.[0])}
          aria-hidden="true"
        />

        {validationError && (
          <p role="alert" className="mt-3 text-sm text-danger" aria-live="polite">
            {validationError}
          </p>
        )}

        <div className="mt-4 flex items-center justify-between gap-3">
          <p className="text-xs text-ink-dim">
            OCR → indicators → ML score and reputation lookups, in parallel
          </p>
          <button
            type="button"
            onClick={submit}
            disabled={loading}
            className="flex items-center gap-2 rounded bg-accent px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:cursor-wait disabled:opacity-70"
          >
            {loading ? (
              <>
                <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" />
                Analyzing…
              </>
            ) : (
              <>
                Analyze
                <ArrowRight aria-hidden="true" className="h-4 w-4" />
              </>
            )}
          </button>
        </div>
      </div>
    </section>
  );
}

const DEMO_TEXT = `⏰ URGENT ACTION REQUIRED — Your account has been temporarily suspended!

Dear Customer,

We detected unusual login activity on your BankCorp Online Banking account. For your safety, your account has been locked and requires IMMEDIATE verification within 24 hours or it will be permanently deleted.

Please confirm your identity at: http://secure-bankcorp-verify.xyz/login?id=7719
Alternative: https://192.168.44.12/verify.html

If you do not verify within 24 hours, funds in the amount of $4,812.33 will be forfeited.

Contact our support team: security-desk@bankcorp-support.xyz

Payment arrangements (crypto accepted if portal fails):

Bitcoin: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Ethereum: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F

Sincerely,
BankCorp Security Desk — 24/7 Protection Team`;
