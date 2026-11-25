"use client";

import Link from "next/link";
import { ArrowUpRight, Eye, ShieldCheck } from "lucide-react";
import type { Alert, Health, Stats, TimelinePoint } from "@/lib/types";
import { attackLabel, duration, hourLabel, isBlockedAction, num, relTime } from "@/lib/format";
import { Sparkline } from "./Charts";
import { Skeleton } from "./ui";

/* ---------- Radial: last 24 hours around the edge, sources to blocks inward ---------- */

const W = 560;
const CX = W / 2;
const CY = 292;
const R_SOURCES = 190;
const R_ALERTS = 135;
const R_BLOCKS = 86;
const R_CORE = 58;
const R_HOURS = 222;
const HOUR_LEN = 40;
const SLOTS = [172, 148, 124, 56, 32];

const rad = (deg: number) => (deg * Math.PI) / 180;
const pt = (r: number, deg: number) => ({ x: CX + r * Math.cos(rad(deg)), y: CY - r * Math.sin(rad(deg)) });
const arc = (r: number, from: number, to: number) => {
  const a = pt(r, from), b = pt(r, to);
  return `M${a.x.toFixed(1)},${a.y.toFixed(1)} A${r},${r} 0 ${Math.abs(from - to) > 180 ? 1 : 0} 1 ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
};

function RingLabel({ r, deg, value, label }: { r: number; deg: number; value: string; label: string }) {
  const { x, y } = pt(r, deg);
  return (
    <g>
      <rect x={x - 42} y={y - 11} width={84} height={22} rx={11} fill="var(--console)" stroke="var(--console-line)" />
      <text x={x} y={y + 4} textAnchor="middle" fontSize={12} fill="var(--console-ink)">
        <tspan fontWeight={600}>{value}</tspan>
        <tspan fill="var(--console-dim)"> {label}</tspan>
      </text>
    </g>
  );
}

function Radial({ stats, timeline, alerts, fresh }: { stats: Stats; timeline: TimelinePoint[]; alerts: Alert[]; fresh: Set<number> }) {
  const types = stats.by_type.slice(0, SLOTS.length);
  const maxType = Math.max(1, ...types.map((t) => t.count));
  const maxHour = Math.max(1, ...timeline.map((p) => p.detected));
  const hours = timeline.slice(-24);
  const share = stats.attackers ? Math.min(1, stats.active_blocks / stats.attackers) : 0;

  const pinging = alerts.filter((a) => fresh.has(a.id));

  const summary = `Last 24 hours: ${num(stats.attackers)} sources, ${num(stats.alerts)} alerts, ${num(stats.blocked)} blocks. ${num(stats.active_blocks)} sources are blocked now. ` +
    types.map((t) => `${attackLabel(String(t.key))} ${num(t.count)}`).join(", ") + ".";

  return (
    <svg viewBox={`0 0 ${W} ${CY + 4}`} className="h-auto w-full" role="img" aria-label={summary}>
      {/* Hour ring: one bar per hour, orange share was blocked */}
      {Array.from({ length: 72 }, (_, i) => {
        const deg = 180 - (i + 0.5) * 2.5;
        const a = pt(R_HOURS - 9, deg), b = pt(R_HOURS - 5, deg);
        return <line key={`t${i}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--console-line)" strokeWidth={1} />;
      })}
      {hours.map((h, i) => {
        const deg = 180 - ((i + 0.5) / hours.length) * 180;
        const len = 3 + (h.detected / maxHour) * HOUR_LEN;
        const blen = h.detected ? (h.blocked / h.detected) * len : 0;
        const a = pt(R_HOURS, deg), b = pt(R_HOURS + len, deg), c = pt(R_HOURS + blen, deg);
        return (
          <g key={h.t}>
            <title>{`${hourLabel(h.t)}: ${num(h.detected)} alerts, ${num(h.blocked)} blocked`}</title>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--console-dim)" strokeOpacity={0.55} strokeWidth={6} />
            {blen > 0 && <line x1={a.x} y1={a.y} x2={c.x} y2={c.y} stroke="var(--signal)" strokeWidth={6} />}
          </g>
        );
      })}
      <text x={CX - R_HOURS - 4} y={CY} textAnchor="end" fontSize={11} fill="var(--console-dim)" className="max-sm:hidden">24 h ago</text>
      <text x={CX + R_HOURS + 4} y={CY} fontSize={11} fill="var(--console-dim)" className="max-sm:hidden">Now</text>

      {/* Rings */}
      {[R_SOURCES, R_ALERTS, R_BLOCKS].map((r) => (
        <path key={r} d={arc(r, 180, 0)} fill="none" stroke="var(--console-line)" strokeWidth={1.25} strokeDasharray={r === R_SOURCES ? "2 5" : undefined} />
      ))}

      {/* Attack types on the outer ring */}
      {types.map((t, i) => {
        const key = String(t.key);
        const deg = SLOTS[i];
        const p = pt(R_SOURCES, deg);
        const r = 4.5 + 6 * Math.sqrt(t.count / maxType);
        const lp = pt(R_SOURCES - r - 24, deg);
        return (
          <g key={key}>
            {pinging.filter((a) => a.attack_type === key).map((a) => (
              <circle key={a.id} cx={p.x} cy={p.y} r={r} fill="none" stroke="var(--signal)" strokeWidth={2} className="ping" style={{ ["--r0" as string]: `${r}px` }} />
            ))}
            <circle cx={p.x} cy={p.y} r={r + 3} fill="var(--console)" />
            <circle cx={p.x} cy={p.y} r={r} fill="var(--signal)" fillOpacity={0.22} stroke="var(--signal)" strokeWidth={1.5} />
            <circle cx={p.x} cy={p.y} r={2.2} fill="var(--signal)" />
            <g className="max-sm:hidden">
              <text x={lp.x} y={lp.y - 2} textAnchor="middle" fontSize={12} fill="var(--console-ink)">{attackLabel(key)}</text>
              <text x={lp.x} y={lp.y + 12} textAnchor="middle" fontSize={12} fill="var(--console-dim)">{num(t.count)}</text>
            </g>
          </g>
        );
      })}

      <RingLabel r={R_SOURCES} deg={90} value={num(stats.attackers)} label="sources" />
      <RingLabel r={R_ALERTS} deg={90} value={num(stats.alerts)} label="alerts" />
      <RingLabel r={R_BLOCKS} deg={90} value={num(stats.blocked)} label="blocks" />

      {/* Core: sources blocked right now, as a share of today's sources */}
      <path d={arc(R_CORE + 9, 180, 0)} fill="none" stroke="var(--console-line)" strokeWidth={4} strokeLinecap="round" />
      {share > 0 && <path d={arc(R_CORE + 9, 180, 180 - share * 180)} fill="none" stroke="var(--signal)" strokeWidth={4} strokeLinecap="round" />}
      <path d={`${arc(R_CORE, 180, 0)} Z`} fill="var(--console-2)" stroke="var(--console-line)" />
      <text x={CX} y={CY - 24} textAnchor="middle" fontSize={34} fontWeight={300} letterSpacing="-1" fill="var(--console-ink)">{num(stats.active_blocks)}</text>
      <text x={CX} y={CY - 7} textAnchor="middle" fontSize={11} fill="var(--console-dim)">blocked now</text>
    </svg>
  );
}

/* ---------- Live feed ---------- */

function Feed({ alerts, fresh, now }: { alerts: Alert[]; fresh: Set<number>; now: number }) {
  const items = alerts.slice(0, 5);
  if (!items.length) return <p className="text-[13px] text-console-dim">Waiting for the first alert.</p>;
  return (
    <ol className="flex flex-col gap-2" aria-live="polite" aria-relevant="additions">
      {items.map((a) => {
        const blocked = isBlockedAction(a.action);
        const hot = fresh.has(a.id);
        const Icon = blocked ? ShieldCheck : Eye;
        return (
          <li
            key={a.id}
            className={`feed-in flex items-start gap-2.5 rounded-xl px-3 py-2.5 text-[13px] transition-colors duration-700 ${hot ? "bg-signal-strong text-white" : "bg-console-2 text-console-ink"}`}
          >
            <span className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-md ${hot ? "bg-white/20" : "bg-console"}`}>
              <Icon size={12} aria-hidden="true" className={hot ? "text-white" : blocked ? "text-signal" : "text-console-dim"} />
            </span>
            <span className="min-w-0">
              <span className="block truncate">
                {attackLabel(a.attack_type)} from <span className="addr">{a.src_ip}</span>
              </span>
              <span className={`block ${hot ? "text-white/85" : "text-console-dim"}`}>
                {blocked ? "Blocked" : "Logged"}, {relTime(a.ts, now)}
              </span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}

/* ---------- Console ---------- */

export function Console({
  stats,
  timeline,
  alerts,
  fresh,
  now,
  health,
}: {
  stats: Stats | null;
  timeline: TimelinePoint[] | null;
  alerts: Alert[];
  fresh: Set<number>;
  now: number;
  health: Health | null;
}) {
  const high = stats?.by_severity.find((s) => Number(s.key) <= 1)?.count ?? 0;
  const medium = stats?.by_severity.filter((s) => Number(s.key) >= 2).reduce((n, s) => n + s.count, 0) ?? 0;

  return (
    <section aria-label="Live view" className="console mb-5 overflow-hidden rounded-[20px] border border-console-line p-5 sm:p-6">
      <div className="grid gap-6 lg:grid-cols-[200px_minmax(0,1fr)_260px] xl:grid-cols-[220px_minmax(0,1fr)_280px]">
        {/* Left: the numbers */}
        <div className="flex flex-col gap-6 sm:flex-row sm:flex-wrap lg:flex-col lg:flex-nowrap">
          <div>
            <h2 className="text-[17px] font-semibold tracking-[-0.01em]">Live view</h2>
            <p className="text-[13px] text-console-dim">Last 24 hours{health ? `, ${health.mode === "demo" ? "simulated sensor" : "Suricata sensor"}` : ""}</p>
          </div>
          {stats ? (
            <>
              <div className="min-w-[180px]">
                <p className="text-[13px] text-console-dim">Alerts</p>
                <p className="figure mt-1 text-[56px]">{num(stats.alerts)}</p>
                <div className="mt-3 h-12 max-w-[220px]">
                  {timeline && <Sparkline values={timeline.map((p) => p.detected)} />}
                </div>
              </div>
              <div>
                <p className="text-[13px] text-console-dim">Median time to block</p>
                <p className="figure mt-1 text-[34px]">{stats.median_time_to_block != null ? duration(stats.median_time_to_block) : "None yet"}</p>
                <p className="mt-1 text-[12px] text-console-dim">From the first packet</p>
              </div>
              <div>
                <p className="mb-2 text-[13px] text-console-dim">By severity</p>
                <ul className="flex gap-2 text-[13px]">
                  <li className="flex items-center gap-1.5 rounded-lg bg-console-2 px-2.5 py-1"><span aria-hidden="true" className="h-2 w-2 rounded-full bg-signal" />{num(high)} high</li>
                  <li className="flex items-center gap-1.5 rounded-lg bg-console-2 px-2.5 py-1"><span aria-hidden="true" className="h-2 w-2 rounded-full" style={{ background: "var(--amber)" }} />{num(medium)} medium</li>
                </ul>
              </div>
            </>
          ) : (
            <Skeleton h={220} dark />
          )}
        </div>

        {/* Middle: the radial */}
        <div className="flex min-w-0 flex-col justify-end">
          {stats && timeline ? <Radial stats={stats} timeline={timeline} alerts={alerts} fresh={fresh} /> : <Skeleton h={280} dark />}
          <p className="mt-3 flex flex-wrap justify-center gap-x-4 gap-y-1 text-[12px] text-console-dim">
            <span>Outer bars: alerts per hour, orange part blocked</span>
            <span>Dots: attack types, sized by alerts</span>
          </p>
        </div>

        {/* Right: the feed */}
        <div className="min-w-0">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-[15px] font-semibold">
              <span aria-hidden="true" className="h-2 w-2 rounded-full" style={{ background: "var(--ok)" }} />
              Live feed
            </h2>
            <Link href="/alerts" aria-label="Open all alerts" className="grid h-8 w-8 place-items-center rounded-lg text-console-dim hover:bg-console-2 hover:text-console-ink">
              <ArrowUpRight size={18} aria-hidden="true" />
            </Link>
          </div>
          <Feed alerts={alerts} fresh={fresh} now={now} />
        </div>
      </div>
    </section>
  );
}
