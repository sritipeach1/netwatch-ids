"use client";

import Link from "next/link";
import { useLive, useApi, useNow } from "@/lib/live";
import type { Stats, TimelinePoint } from "@/lib/types";
import { attackLabel, duration, isBlockedAction, num, relTime } from "@/lib/format";
import { BarList, TimelineChart } from "@/components/Charts";
import { AlertsTable } from "@/components/AlertRows";
import { Console } from "@/components/Console";
import { WorldMap } from "@/components/WorldMap";
import { EmptyState, ErrorNote, PageHeader, Panel, Skeleton, TallyBar } from "@/components/ui";

function uptime(s: number) {
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`;
}

export default function Overview() {
  const stats = useApi<Stats>("/api/stats?hours=24");
  const timeline = useApi<TimelinePoint[]>("/api/timeline?hours=24");
  const { alerts, fresh, health } = useLive();
  const now = useNow(1000);
  const s = stats.data;

  const lastAlert = alerts[0];
  const lastBlocked = alerts.find((a) => isBlockedAction(a.action));
  const bySource = alerts.reduce(
    (acc, a) => ({ ...acc, [a.source]: (acc[a.source] ?? 0) + 1 }),
    {} as Record<string, number>,
  );
  const sigCount = bySource.suricata ?? 0;
  const mlCount = bySource.ml ?? 0;
  const loggedOnly = alerts.filter((a) => !isBlockedAction(a.action)).length;

  return (
    <>
      <PageHeader title="Overview" note={lastAlert ? `Last alert ${relTime(lastAlert.ts, now)}` : undefined} />

      {stats.error && !s ? (
        <ErrorNote message={stats.error} onRetry={stats.reload} />
      ) : (
        <>
          <Console stats={s} timeline={timeline.data} alerts={alerts} fresh={fresh} now={now} health={health} />

          <div className="mb-5 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
            <Panel title="Attack types" note="Alerts by type, last 24 hours" href="/alerts">
              {s ? (
                s.by_type.length ? (
                  <ul className="flex flex-col gap-3.5">
                    {s.by_type.map((t) => (
                      <li key={String(t.key)} className="text-[13px]">
                        <div className="mb-1.5 flex justify-between gap-3"><span className="text-ink-2">{attackLabel(String(t.key))}</span><span className="font-semibold">{num(t.count)}</span></div>
                        <TallyBar value={t.count} max={s.by_type[0].count} color="var(--signal)" />
                      </li>
                    ))}
                  </ul>
                ) : (
                  <EmptyState title="No attacks yet" body="Use Simulate attack to send some traffic." />
                )
              ) : <Skeleton h={200} />}
            </Panel>

            <Panel title="Where it comes from" note="Alerts by source country" className="md:col-span-2">
              {s ? (
                <div className="grid gap-5 sm:grid-cols-[minmax(0,1fr)_220px] sm:items-center">
                  <WorldMap countries={s.by_country} />
                  <BarList rows={s.by_country.slice(0, 5).map((c) => ({ label: String(c.key), value: c.count }))} color="var(--ink-2)" />
                </div>
              ) : <Skeleton h={200} />}
            </Panel>

            <Panel title="Response" note="What happened after detection" href="/blocks">
              {s ? (
                <div className="flex h-full flex-col gap-4">
                  <div>
                    <p className="figure text-[52px]">{num(s.active_blocks)}</p>
                    <p className="mt-1 text-[13px] text-ink-2">sources blocked right now</p>
                  </div>
                  <dl className="grid gap-2 border-t border-rule pt-3 text-[13px]">
                    <div className="flex justify-between gap-3"><dt className="text-ink-2">Blocks today</dt><dd className="font-semibold">{num(s.blocked)}</dd></div>
                    <div className="flex justify-between gap-3"><dt className="text-ink-2">Median time to block</dt><dd className="font-semibold">{s.median_time_to_block != null ? duration(s.median_time_to_block) : "None yet"}</dd></div>
                    <div className="flex justify-between gap-3"><dt className="text-ink-2" title={`Among the latest ${num(alerts.length)} alerts`}>Logged only, recent</dt><dd className="font-semibold">{num(loggedOnly)}</dd></div>
                  </dl>
                </div>
              ) : <Skeleton h={200} />}
            </Panel>
          </div>

          <div className="mb-5 grid gap-5 xl:grid-cols-3">
            <Panel title="Alerts per hour" note="Last 24 hours" className="xl:col-span-2">
              {timeline.data ? <TimelineChart points={timeline.data} /> : <Skeleton h={260} />}
            </Panel>
            <Panel title="Who raised them" note={`Detector behind the latest ${num(alerts.length)} alerts`} href="/analysis">
              {alerts.length ? (
                <div className="flex flex-col gap-5">
                  {[
                    { label: "Signature rules", value: sigCount, color: "var(--rules)", note: "Known patterns, from Suricata" },
                    { label: "Flow classifier", value: mlCount, color: "var(--signal)", note: "Behaviour over 60-second windows" },
                  ].map((d) => (
                    <div key={d.label}>
                      <div className="flex items-baseline justify-between gap-3">
                        <span className="text-[14px] font-semibold">{d.label}</span>
                        <span className="figure text-[34px]">{num(d.value)}</span>
                      </div>
                      <p className="mb-2 text-[13px] text-ink-2">{d.note}</p>
                      <TallyBar value={d.value} max={alerts.length} color={d.color} segments={30} />
                    </div>
                  ))}
                  <p className="text-[13px] text-ink-2">Each catches attacks the other misses. Detection analysis has the breakdown.</p>
                </div>
              ) : <EmptyState title="Nothing raised yet" body="Detector counts appear once alerts come in." />}
            </Panel>
          </div>

          <Panel title="Latest alerts" note="Newest first" href="/alerts" className="mb-5">
            {alerts.length ? (
              <AlertsTable rows={alerts.slice(0, 8)} fresh={fresh} now={now} compact />
            ) : (
              <EmptyState title="Quiet so far" body="Alerts appear here as they happen. Nothing suspicious has been seen yet." />
            )}
          </Panel>

          {/* Status strip */}
          <section aria-label="Sensor timeline" className="flex flex-col gap-3 rounded-2xl border border-rule bg-surface p-3 sm:flex-row sm:items-center sm:gap-0">
            {[
              { label: "Sensor running for", value: health ? uptime(health.uptime_s) : "Unknown" },
              { label: "Last alert", value: lastAlert ? relTime(lastAlert.ts, now) : "None yet" },
              { label: "Last block", value: lastBlocked ? `${relTime(lastBlocked.ts, now)}, ${lastBlocked.src_ip}` : "None yet" },
            ].map((it, i) => (
              <div key={it.label} className={`flex flex-1 items-center gap-3 px-2 ${i ? "sm:border-l sm:border-rule sm:pl-4" : ""}`}>
                <div>
                  <p className="text-[12px] text-ink-3">{it.label}</p>
                  <p className="text-[14px] font-semibold">{it.value}</p>
                </div>
              </div>
            ))}
            <Link href="/alerts" className="rounded-lg bg-signal-strong px-4 py-2.5 text-center text-[14px] font-semibold text-white hover:bg-[#b3470c] sm:ml-2">
              View all alerts
            </Link>
          </section>
        </>
      )}
    </>
  );
}
