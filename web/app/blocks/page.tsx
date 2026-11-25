"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi, useNow } from "@/lib/live";
import type { Block } from "@/lib/types";
import { attackLabel, clock, duration, num } from "@/lib/format";
import { EmptyState, ErrorNote, PageHeader, Skeleton } from "@/components/ui";

function left(expires: number, now: number) {
  const s = expires - now;
  if (s <= 0) return "Expired";
  return duration(s);
}

/** How much of the block is left, as a thin bar. */
function Remaining({ b, now }: { b: Block; now: number }) {
  const total = Math.max(1, b.expires - b.ts);
  const frac = Math.min(1, Math.max(0, (b.expires - now) / total));
  return (
    <div className="flex min-w-[120px] flex-col gap-1.5">
      <span>{left(b.expires, now)}<span className="text-ink-3"> of {duration(total)}</span></span>
      <span aria-hidden="true" className="h-1.5 w-full rounded-full bg-rule">
        <span className="block h-full rounded-full bg-signal" style={{ width: `${frac * 100}%` }} />
      </span>
    </div>
  );
}

export default function BlocksPage() {
  const { data, error, loading, reload } = useApi<Block[]>("/api/blocks", 10000);
  const now = useNow(1000);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const unblock = async (ip: string) => {
    setMsg(null);
    try {
      await api(`/api/blocks/${encodeURIComponent(ip)}/unblock`, { method: "POST" });
      setConfirm(null);
      setMsg(`Unblocked ${ip}.`);
      reload();
    } catch (e) {
      setConfirm(null);
      setMsg(e instanceof ApiError && e.status === 403 ? "Unblocking needs an API key when the sensor is in live mode." : e instanceof ApiError ? e.message : "Couldn't unblock that source. Try again.");
    }
  };

  const repeat = data?.filter((b) => b.expires - b.ts > 3 * 3600).length ?? 0;
  const latencies = (data ?? []).map((b) => b.latency).filter((v): v is number => v != null).sort((a, b) => a - b);
  const median = latencies.length ? latencies[Math.floor(latencies.length / 2)] : null;
  const th = "py-2.5 pr-4 text-[12px] font-medium text-ink-3";

  return (
    <>
      <PageHeader
        title="Blocked sources"
        description="Addresses the response engine is dropping right now. Blocks expire on their own, and repeat offenders are blocked for 24 hours instead of 1."
      />

      {data && data.length > 0 && (
        <section aria-label="Summary" className="mb-5 grid grid-cols-1 gap-px overflow-hidden rounded-2xl border border-rule bg-rule sm:grid-cols-3">
          {[
            { label: "Blocked now", value: num(data.length) },
            { label: "Repeat offenders", value: num(repeat), note: "Blocked for 24 hours" },
            { label: "Median time to block", value: median != null ? duration(median) : "None", note: "Among current blocks" },
          ].map((m) => (
            <div key={m.label} className="bg-surface px-5 py-4">
              <p className="text-[13px] text-ink-2">{m.label}</p>
              <p className="figure mt-1.5 text-[40px]">{m.value}</p>
              {m.note && <p className="mt-1 text-[12px] text-ink-3">{m.note}</p>}
            </div>
          ))}
        </section>
      )}

      <div className="rounded-2xl border border-rule bg-surface p-5">
        {msg && <p role="status" className="mb-3 text-ink-2">{msg}</p>}
        {error && !data ? (
          <ErrorNote message={error} onRetry={reload} />
        ) : loading && !data ? (
          <Skeleton h={160} />
        ) : data && data.length ? (
          <div className="relative -mx-5 overflow-x-auto px-5">
            <table className="w-full min-w-[860px] text-left text-[14px]">
              <thead>
                <tr className="border-b border-rule-strong">
                  <th className={th}>Source</th>
                  <th className={th}>Attack</th>
                  <th className={th}>Why it was blocked</th>
                  <th className={th}>Time to block</th>
                  <th className={th}>Blocked at</th>
                  <th className={th}>Time left</th>
                  <th className="py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {data.map((b) => (
                  <tr key={b.id} className="border-b border-rule align-top last:border-b-0 hover:bg-surface-2/60">
                    <td className="addr py-3 pr-4 font-medium whitespace-nowrap">{b.ip}</td>
                    <td className="py-3 pr-4 whitespace-nowrap">{b.attack_type ? attackLabel(b.attack_type) : "None"}</td>
                    <td className="py-3 pr-4 text-ink-2">{b.reason}</td>
                    <td className="py-3 pr-4 whitespace-nowrap">{b.latency != null ? duration(b.latency) : "None"}</td>
                    <td className="py-3 pr-4 whitespace-nowrap">{clock(b.ts)}</td>
                    <td className="py-3 pr-4 whitespace-nowrap"><Remaining b={b} now={now} /></td>
                    <td className="py-3 text-right whitespace-nowrap">
                      {confirm === b.ip ? (
                        <span className="inline-flex gap-2">
                          <button type="button" onClick={() => unblock(b.ip)} className="rounded-lg bg-ink px-3 py-1.5 text-[13px] font-semibold text-surface hover:opacity-90">Unblock {b.ip}</button>
                          <button type="button" onClick={() => setConfirm(null)} className="rounded-lg border border-rule-strong px-3 py-1.5 text-[13px] font-semibold hover:bg-surface-2">Keep blocked</button>
                        </span>
                      ) : (
                        <button type="button" onClick={() => setConfirm(b.ip)} className="rounded-lg border border-rule-strong px-3 py-1.5 text-[13px] font-semibold hover:bg-surface-2">Unblock</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No sources are blocked" body="When an alert crosses the response threshold, the source shows up here with the reason and how long the block lasts." />
        )}
      </div>
    </>
  );
}
