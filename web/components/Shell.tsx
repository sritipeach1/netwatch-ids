"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ChartSpline, Crosshair, Radar, ShieldBan, Siren } from "lucide-react";
import { useLive } from "@/lib/live";
import { SimulatePanel } from "./SimulatePanel";
import { Logo } from "./Logo";

const NAV = [
  { href: "/", label: "Overview", icon: Radar },
  { href: "/alerts", label: "Alerts", icon: Siren },
  { href: "/blocks", label: "Blocked sources", icon: ShieldBan },
  { href: "/analysis", label: "Detection analysis", icon: ChartSpline },
];

const RESPONSE_LABEL: Record<string, string> = {
  off: "Response off",
  "dry-run": "Dry run, nothing blocked",
  simulated: "Simulated blocking",
  enforce: "Enforcing with nftables",
};

function StatusDot({ on }: { on: boolean }) {
  return (
    <span aria-hidden="true" className="relative inline-flex h-2 w-2">
      <span className="h-2 w-2 rounded-full" style={{ background: on ? "var(--ok)" : "var(--rule-strong)" }} />
    </span>
  );
}

function SimulateButton({ onClick, full = false }: { onClick: () => void; full?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center justify-center gap-2 rounded-lg bg-signal-strong px-3.5 py-2 text-[14px] font-semibold text-white hover:bg-[#b3470c] ${full ? "w-full" : ""}`}
    >
      <Crosshair size={16} aria-hidden="true" />
      Simulate attack
    </button>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { health, connected, error } = useLive();
  const [simOpen, setSimOpen] = useState(false);
  const demo = health?.mode === "demo";
  const status = error ? "API unreachable" : connected ? "Live" : "Connecting";
  const isActive = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));

  return (
    <>
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>

      <div className="min-h-screen lg:grid lg:grid-cols-[236px_minmax(0,1fr)]">
        {/* Desktop sidebar */}
        <aside className="hidden border-r border-rule lg:block">
          <div className="sticky top-0 flex h-screen flex-col gap-6 px-4 py-5">
            <Link href="/" className="px-2" aria-label="NetWatch overview"><Logo /></Link>
            {demo && <SimulateButton full onClick={() => setSimOpen(true)} />}
            <nav aria-label="Main">
              <ul className="flex flex-col gap-0.5">
                {NAV.map(({ href, label, icon: Icon }) => {
                  const active = isActive(href);
                  return (
                    <li key={href}>
                      <Link
                        href={href}
                        aria-current={active ? "page" : undefined}
                        className={`flex items-center gap-3 rounded-lg px-2.5 py-2 text-[14px] ${active ? "bg-surface font-semibold text-ink shadow-[inset_0_0_0_1px_var(--rule)]" : "text-ink-2 hover:bg-surface-2 hover:text-ink"}`}
                      >
                        <Icon size={17} aria-hidden="true" className={active ? "text-signal-strong" : ""} />
                        {label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </nav>

            <div className="mt-auto rounded-xl border border-rule bg-surface p-3.5 text-[13px]">
              <div className="flex items-center gap-2 font-semibold" role="status">
                <StatusDot on={connected && !error} />
                {status}
              </div>
              <dl className="mt-2 grid gap-1 text-ink-2">
                <div className="flex justify-between gap-2"><dt>Sensor</dt><dd className="text-ink">{health ? (demo ? "Simulated" : "Suricata") : "Unknown"}</dd></div>
                <div className="flex justify-between gap-2"><dt>Classifier</dt><dd className="text-ink">{health ? (health.model_loaded ? "Loaded" : "Not loaded") : "Unknown"}</dd></div>
              </dl>
              {health && <p className="mt-2 border-t border-rule pt-2 text-ink-2">{RESPONSE_LABEL[health.response_mode] ?? health.response_mode}</p>}
            </div>
          </div>
        </aside>

        <div className="min-w-0">
          {/* Phone and tablet header */}
          <header className="border-b border-rule lg:hidden">
            <div className="flex items-center gap-3 px-4 py-3">
              <Link href="/" aria-label="NetWatch overview"><Logo /></Link>
              <span className="ml-auto flex items-center gap-1.5 text-[13px] text-ink-2" role="status">
                <StatusDot on={connected && !error} />
                {status}
              </span>
              {demo && <SimulateButton onClick={() => setSimOpen(true)} />}
            </div>
            <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-3 pb-2">
              {NAV.map(({ href, label }) => {
                const active = isActive(href);
                return (
                  <Link
                    key={href}
                    href={href}
                    aria-current={active ? "page" : undefined}
                    className={`whitespace-nowrap rounded-lg px-3 py-2 text-[14px] ${active ? "bg-surface font-semibold text-ink" : "text-ink-2 hover:text-ink"}`}
                  >
                    {label}
                  </Link>
                );
              })}
            </nav>
          </header>

          <main id="main" className="mx-auto max-w-[1280px] px-4 pb-12 pt-6 sm:px-6 lg:px-8 lg:pt-7">
            {children}
          </main>
          <footer className="mx-auto max-w-[1280px] px-4 pb-8 text-[13px] text-ink-2 sm:px-6 lg:px-8">
            {demo
              ? "Demo mode: a simulator generates the traffic and attackers. Detection, scoring and response run the same code as live mode."
              : health
                ? "Live mode: reading events from Suricata."
                : null}
          </footer>
        </div>
      </div>

      {demo && <SimulatePanel open={simOpen} onClose={() => setSimOpen(false)} />}
    </>
  );
}
