export default function Card({ title, icon, children, className = '' }) {
  const Icon = icon;
  return (
    <section className={`rounded border border-line bg-surface p-5 ${className}`}>
      <h2 className="mb-4 flex items-center gap-2 text-[15px] font-semibold text-ink">
        {Icon && <Icon aria-hidden="true" className="h-4 w-4 text-ink-dim" />}
        {title}
      </h2>
      {children}
    </section>
  );
}
