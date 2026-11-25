/** NetWatch mark: three sensor arcs and the point where something crossed them. */
export function LogoMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 30 30" aria-hidden="true">
      <rect width="30" height="30" rx="8" fill="var(--console)" />
      <g fill="none" strokeLinecap="round" strokeWidth="2">
        <path d="M7 23 a5 5 0 0 1 5 -5" stroke="var(--console-dim)" />
        <path d="M7 23 a10 10 0 0 1 10 -10" stroke="var(--console-dim)" opacity="0.75" />
        <path d="M7 23 a15.5 15.5 0 0 1 15.5 -15.5" stroke="var(--console-dim)" opacity="0.5" />
      </g>
      <circle cx="17.6" cy="13.4" r="2.6" fill="var(--signal)" />
    </svg>
  );
}

export function Logo() {
  return (
    <span className="flex items-center gap-2.5 text-[19px] font-semibold tracking-[-0.02em] text-ink">
      <LogoMark />
      NetWatch
    </span>
  );
}
