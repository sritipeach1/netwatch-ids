"use client";

import { useEffect, useRef, useState } from "react";
import type { TimelinePoint } from "@/lib/types";
import { hourLabel, num } from "@/lib/format";
import { TallyBar } from "./ui";

function niceMax(v: number): number {
  if (v <= 4) return 4;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  for (const f of [1, 2, 2.5, 5, 10]) if (v <= f * pow) return f * pow;
  return 10 * pow;
}

const H = 240;
const M = { l: 38, r: 16, t: 12, b: 26 };

export function TimelineChart({ points }: { points: TimelinePoint[] }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(640);
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e.contentRect.width))));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const n = points.length;
  const max = niceMax(Math.max(1, ...points.map((p) => Math.max(p.detected, p.blocked))));
  const x = (i: number) => M.l + (n <= 1 ? 0 : (i / (n - 1)) * (w - M.l - M.r));
  const y = (v: number) => M.t + (1 - v / max) * (H - M.t - M.b);
  const line = (key: "detected" | "blocked") => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join("");
  const area = n ? `${line("detected")}L${x(n - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z` : "";
  const yTicks = [0, 1, 2, 3, 4].map((k) => (max / 4) * k);
  const step = Math.max(1, Math.ceil(n / 6), Math.ceil(n / Math.max(2, Math.floor((w - M.l - M.r) / 74))));

  const setFromPointer = (clientX: number) => {
    const rect = wrap.current?.getBoundingClientRect();
    if (!rect || n === 0) return;
    const i = Math.round(((clientX - rect.left - M.l) / (w - M.l - M.r)) * (n - 1));
    setHover(Math.min(n - 1, Math.max(0, i)));
  };

  const hp = hover != null ? points[hover] : null;
  const last = n - 1;

  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-ink-2">
        <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--ink-2)" }} />Alerts raised</span>
        <span className="flex items-center gap-1.5"><span className="inline-block h-0 w-4 border-t-2 border-dashed" style={{ borderColor: "var(--signal-strong)" }} />Sources blocked</span>
      </div>
      <div ref={wrap} className="relative w-full overflow-hidden" style={{ height: H }}>
        <svg
          width={w}
          height={H}
          role="img"
          aria-label={`Alerts raised and sources blocked per hour over the last ${n} hours`}
          tabIndex={0}
          onPointerMove={(e) => setFromPointer(e.clientX)}
          onPointerLeave={() => setHover(null)}
          onKeyDown={(e) => {
            if (e.key === "ArrowLeft") setHover((h) => Math.max(0, (h ?? n) - 1));
            if (e.key === "ArrowRight") setHover((h) => Math.min(n - 1, (h ?? -1) + 1));
            if (e.key === "Escape") setHover(null);
          }}
          onBlur={() => setHover(null)}
        >
          {yTicks.map((t) => (
            <g key={t}>
              <line x1={M.l} x2={w - M.r} y1={y(t)} y2={y(t)} stroke="var(--rule)" strokeWidth={1} />
              <text x={M.l - 8} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--ink-3)">{num(Math.round(t))}</text>
            </g>
          ))}
          {points.map((p, i) => i % step === 0 && (
            <text key={p.t} x={x(i)} y={H - 6} textAnchor="middle" fontSize={11} fill="var(--ink-3)">{hourLabel(p.t)}</text>
          ))}
          {n > 1 && <path d={area} fill="var(--ink-2)" opacity={0.09} />}
          {n > 1 && <path d={line("detected")} fill="none" stroke="var(--ink-2)" strokeWidth={1.75} strokeLinejoin="round" strokeLinecap="round" />}
          {n > 1 && <path d={line("blocked")} fill="none" stroke="var(--signal-strong)" strokeWidth={2} strokeDasharray="5 4" strokeLinejoin="round" strokeLinecap="round" />}
          {n > 0 && hover == null && (
            <>
              <circle cx={x(last)} cy={y(points[last].detected)} r={4} fill="var(--ink-2)" stroke="var(--surface)" strokeWidth={2} />
              <circle cx={x(last)} cy={y(points[last].blocked)} r={4} fill="var(--signal-strong)" stroke="var(--surface)" strokeWidth={2} />
            </>
          )}
          {hp && hover != null && (
            <>
              <line x1={x(hover)} x2={x(hover)} y1={M.t} y2={H - M.b} stroke="var(--rule-strong)" strokeWidth={1} />
              <circle cx={x(hover)} cy={y(hp.detected)} r={4} fill="var(--ink-2)" stroke="var(--surface)" strokeWidth={2} />
              <circle cx={x(hover)} cy={y(hp.blocked)} r={4} fill="var(--signal-strong)" stroke="var(--surface)" strokeWidth={2} />
            </>
          )}
        </svg>
        {hp && hover != null && (
          <div
            className="pointer-events-none absolute z-10 rounded-lg border border-rule-strong bg-surface px-3 py-2 text-[13px] shadow-[0_4px_16px_rgba(28,33,27,0.12)]"
            style={{ left: Math.min(Math.max(x(hover) + 10, 0), w - 168), top: 8, width: 158 }}
          >
            <div className="mb-1 font-semibold">{hourLabel(hp.t)} to {hourLabel(hp.t + 3600)}</div>
            <div className="flex justify-between"><span className="text-ink-2">Alerts</span><span>{num(hp.detected)}</span></div>
            <div className="flex justify-between"><span className="text-ink-2">Blocked</span><span>{num(hp.blocked)}</span></div>
          </div>
        )}
      </div>
      <details className="mt-2 text-[13px] text-ink-2">
        <summary className="cursor-pointer select-none py-1">View as table</summary>
        <div className="max-h-56 overflow-auto">
          <table className="w-full text-left">
            <thead><tr className="text-ink-3"><th className="py-1 pr-4 font-normal">Hour starting</th><th className="py-1 pr-4 font-normal">Alerts</th><th className="py-1 font-normal">Blocked</th></tr></thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.t} className="border-t border-rule"><td className="py-1 pr-4">{hourLabel(p.t)}</td><td className="py-1 pr-4">{num(p.detected)}</td><td className="py-1">{num(p.blocked)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

export type BarRow = { label: string; value: number; display?: string };

/** One series of tally bars, value at the end of each row. */
export function BarList({ rows, color = "var(--ink)", max }: { rows: BarRow[]; color?: string; max?: number }) {
  const top = max ?? (Math.max(0, ...rows.map((r) => r.value)) || 1);
  return (
    <ul className="flex flex-col gap-3">
      {rows.map((r) => (
        <li key={r.label} title={`${r.label}: ${r.display ?? num(r.value)}`} className="grid grid-cols-[minmax(0,7.5rem)_1fr_auto] items-center gap-3 text-[13px]">
          <span className="truncate text-ink-2">{r.label}</span>
          <TallyBar value={r.value} max={top} color={color} />
          <span className="w-10 text-right font-semibold">{r.display ?? num(r.value)}</span>
        </li>
      ))}
    </ul>
  );
}

/** Small trend line for the console. */
export function Sparkline({ values, width = 180, height = 48 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const max = Math.max(1, ...values);
  const x = (i: number) => 3 + (i / (values.length - 1)) * (width - 8);
  const y = (v: number) => 4 + (1 - v / max) * (height - 8);
  const d = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const last = values.length - 1;
  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true" className="overflow-visible">
      <path d={d} fill="none" stroke="var(--console-ink)" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      <circle cx={x(last)} cy={y(values[last])} r={3.5} fill="var(--console-ink)" />
    </svg>
  );
}
