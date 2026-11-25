import Link from "next/link";
import { ArrowUpRight, Eye, Info, ShieldCheck } from "lucide-react";
import { isBlockedAction } from "@/lib/format";

export function PageHeader({ title, note, description, actions }: { title: string; note?: string; description?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="flex flex-wrap items-baseline gap-x-3 text-[28px] font-semibold leading-tight tracking-[-0.025em]">
          {title}
          {note && <span className="text-[14px] font-normal tracking-normal text-ink-2">{note}</span>}
        </h1>
        {description && <p className="mt-1 max-w-[66ch] text-ink-2">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Light card. `href` adds a corner link to the page with the full view. */
export function Panel({
  title,
  note,
  href,
  aside,
  children,
  className = "",
}: {
  title: string;
  note?: string;
  href?: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`min-w-0 rounded-2xl border border-rule bg-surface p-5 ${className}`}>
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-[17px] font-semibold leading-snug tracking-[-0.01em]">{title}</h2>
          {note && <p className="text-[13px] text-ink-3">{note}</p>}
        </div>
        {aside}
        {href && (
          <Link
            href={href}
            aria-label={`Open ${title.toLowerCase()}`}
            className="-mr-1 -mt-1 grid h-8 w-8 shrink-0 place-items-center rounded-lg text-ink-2 hover:bg-surface-2 hover:text-ink"
          >
            <ArrowUpRight size={18} aria-hidden="true" />
          </Link>
        )}
      </div>
      {children}
    </section>
  );
}

export function SeverityBadge({ severity }: { severity: number }) {
  const high = severity <= 1;
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px] font-medium">
      <span aria-hidden="true" className="h-2 w-2 rounded-full" style={{ background: high ? "var(--signal-strong)" : "var(--amber)" }} />
      {high ? "High" : severity === 2 ? "Medium" : "Low"}
    </span>
  );
}

export function ActionPill({ action }: { action: string }) {
  const blocked = isBlockedAction(action);
  const dry = action.startsWith("dry-run");
  return blocked ? (
    <span className="inline-flex items-center gap-1 rounded-md border border-signal-strong/60 bg-[#f3dccb] px-2 py-0.5 text-[12px] font-semibold text-signal-text">
      <ShieldCheck size={12} aria-hidden="true" />
      {dry ? "Would block" : "Blocked"}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-md border border-rule-strong px-2 py-0.5 text-[12px] text-ink-2">
      <Eye size={12} aria-hidden="true" />
      Logged only
    </span>
  );
}

export function EmptyState({ title, body, dark = false }: { title: string; body: string; dark?: boolean }) {
  return (
    <div className="flex flex-col items-start gap-1 px-1 py-6">
      <Info size={18} aria-hidden="true" className={dark ? "text-console-dim" : "text-ink-3"} />
      <p className="font-semibold">{title}</p>
      <p className={`max-w-[56ch] ${dark ? "text-console-dim" : "text-ink-2"}`}>{body}</p>
    </div>
  );
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-2xl border border-rule-strong bg-surface p-5 text-ink-2">
      <p className="font-semibold text-ink">Couldn&apos;t load this data</p>
      <p className="mb-3">{message}. Check that the API is running and that NEXT_PUBLIC_API_URL points to it.</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="rounded-lg border border-rule-strong px-3 py-1.5 text-[13px] font-semibold hover:bg-surface-2">
          Try again
        </button>
      )}
    </div>
  );
}

export function Skeleton({ h = 120, dark = false }: { h?: number; dark?: boolean }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-xl ${dark ? "bg-console-2" : "bg-surface-2"}`} style={{ height: h }} />;
}

/** Segmented bar, like a tally: filled dashes for the value, faint ones for the rest. */
export function TallyBar({ value, max, color = "var(--ink)", segments = 24, dark = false }: { value: number; max: number; color?: string; segments?: number; dark?: boolean }) {
  const filled = max > 0 ? Math.max(value > 0 ? 1 : 0, Math.round((value / max) * segments)) : 0;
  return (
    <span aria-hidden="true" className="flex h-2 flex-1 gap-[2px]">
      {Array.from({ length: segments }, (_, i) => (
        <span
          key={i}
          className="h-full flex-1 rounded-[1px]"
          style={{ background: i < filled ? color : dark ? "var(--console-line)" : "var(--rule)" }}
        />
      ))}
    </span>
  );
}
