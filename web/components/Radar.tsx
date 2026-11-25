"use client";

import { pct } from "@/lib/format";

export type RadarSeries = { key: string; name: string; color: string; fill: number; dashed?: boolean; values: number[] };

const S = 380;
const C = S / 2;
const R = 118;

const at = (i: number, n: number, r: number) => {
  const a = -Math.PI / 2 + (i / n) * Math.PI * 2;
  return { x: C + r * Math.cos(a), y: C + 6 + r * Math.sin(a) };
};

/** Detection rate per attack type, one polygon per detector. Values are 0..1. */
export function Radar({ axes, series }: { axes: string[]; series: RadarSeries[] }) {
  const n = axes.length;
  const poly = (vals: number[]) => vals.map((v, i) => { const p = at(i, n, Math.max(0.02, v) * R); return `${p.x.toFixed(1)},${p.y.toFixed(1)}`; }).join(" ");
  const label = `Detection rate by attack type. ${series.map((s) => `${s.name}: ${axes.map((a, i) => `${a} ${pct(s.values[i])}`).join(", ")}`).join(". ")}.`;

  return (
    <svg viewBox={`-70 6 ${S + 140} ${S - 12}`} className="mx-auto h-auto w-full max-w-[480px]" role="img" aria-label={label}>
      {[0.25, 0.5, 0.75, 1].map((f) => (
        <polygon key={f} points={poly(axes.map(() => f))} fill="none" stroke="var(--console-line)" strokeWidth={1} />
      ))}
      {axes.map((a, i) => {
        const p = at(i, n, R);
        const l = at(i, n, R + 26);
        const anchor = Math.abs(l.x - C) < 8 ? "middle" : l.x < C ? "end" : "start";
        return (
          <g key={a}>
            <line x1={C} y1={C + 6} x2={p.x} y2={p.y} stroke="var(--console-line)" />
            <text x={l.x} y={l.y + 4} textAnchor={anchor} fontSize={13} fill="var(--console-ink)">{a}</text>
          </g>
        );
      })}
      <text x={C + 4} y={C + 6 - R * 0.5 - 4} fontSize={10} fill="var(--console-dim)">50%</text>
      <text x={C + 4} y={C + 6 - R - 4} fontSize={10} fill="var(--console-dim)">100%</text>
      {series.map((s) => (
        <g key={s.key}>
          <polygon
            points={poly(s.values)}
            fill={s.color}
            fillOpacity={s.fill}
            stroke={s.color}
            strokeWidth={s.dashed ? 1.5 : 2}
            strokeDasharray={s.dashed ? "4 4" : undefined}
            strokeLinejoin="round"
          />
          {!s.dashed && s.values.map((v, i) => { const p = at(i, n, Math.max(0.02, v) * R); return <circle key={i} cx={p.x} cy={p.y} r={3} fill={s.color} />; })}
        </g>
      ))}
    </svg>
  );
}
