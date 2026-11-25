"use client";

import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { useLive, useNow } from "@/lib/live";
import { ATTACK_LABELS, attackLabel, isBlockedAction } from "@/lib/format";
import { AlertsTable } from "@/components/AlertRows";
import { EmptyState, PageHeader } from "@/components/ui";

const PAGE = 20;

export default function AlertsPage() {
  const { alerts, fresh, error } = useLive();
  const now = useNow(1000);
  const [q, setQ] = useState("");
  const [type, setType] = useState("all");
  const [resp, setResp] = useState("all");
  const [page, setPage] = useState(0);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return alerts.filter((a) => {
      if (type !== "all" && a.attack_type !== type) return false;
      if (resp === "blocked" && !isBlockedAction(a.action)) return false;
      if (resp === "logged" && isBlockedAction(a.action)) return false;
      if (!needle) return true;
      return [a.src_ip, a.country ?? "", a.signature, attackLabel(a.attack_type), a.technique ?? ""].some((v) => v.toLowerCase().includes(needle));
    });
  }, [alerts, q, type, resp]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const cur = Math.min(page, pages - 1);
  const slice = rows.slice(cur * PAGE, cur * PAGE + PAGE);
  const reset = <T,>(set: (v: T) => void) => (v: T) => { set(v); setPage(0); };

  const field = "h-10 rounded-lg border border-rule-strong bg-paper/50 px-3 text-[14px] hover:border-ink-3";

  return (
    <>
      <PageHeader title="Alerts" note={alerts.length ? `${alerts.length} most recent` : undefined} description="Everything the signature rules and the flow classifier have raised, newest first." />
      <div className="rounded-2xl border border-rule bg-surface p-5">
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <label className="flex min-w-[min(100%,240px)] flex-1 flex-col gap-1.5 text-[13px] font-medium">
            Search
            <span className="relative">
              <Search size={16} aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" />
              <input
                type="search"
                value={q}
                onChange={(e) => reset(setQ)(e.target.value)}
                placeholder="Address, country or attack"
                className={`${field} w-full pl-9 font-normal`}
              />
            </span>
          </label>
          <label className="flex flex-col gap-1.5 text-[13px] font-medium">
            Attack type
            <select value={type} onChange={(e) => reset(setType)(e.target.value)} className={field}>
              <option value="all">All types</option>
              {Object.entries(ATTACK_LABELS).filter(([k]) => k !== "other").map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1.5 text-[13px] font-medium">
            Response
            <select value={resp} onChange={(e) => reset(setResp)(e.target.value)} className={field}>
              <option value="all">All responses</option>
              <option value="blocked">Blocked</option>
              <option value="logged">Logged only</option>
            </select>
          </label>
        </div>

        {slice.length ? (
          <AlertsTable rows={slice} fresh={fresh} now={now} />
        ) : error ? (
          <EmptyState title="Can't reach the API" body="Check that the API is running and that NEXT_PUBLIC_API_URL points to it." />
        ) : (
          <EmptyState
            title={alerts.length ? "No alerts match these filters" : "No alerts yet"}
            body={alerts.length ? "Clear the search or switch a filter back to All." : "Alerts appear here as they happen."}
          />
        )}

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-[13px] text-ink-2">
          <span>{rows.length ? `${cur * PAGE + 1} to ${Math.min(rows.length, cur * PAGE + PAGE)} of ${rows.length}` : "0 alerts"}</span>
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => setPage(cur - 1)} disabled={cur === 0} className="rounded-lg border border-rule-strong px-3 py-1.5 font-semibold enabled:hover:bg-surface-2 disabled:text-ink-3 disabled:opacity-60">Previous</button>
            <span>Page {cur + 1} of {pages}</span>
            <button type="button" onClick={() => setPage(cur + 1)} disabled={cur >= pages - 1} className="rounded-lg border border-rule-strong px-3 py-1.5 font-semibold enabled:hover:bg-surface-2 disabled:text-ink-3 disabled:opacity-60">Next</button>
          </div>
        </div>
      </div>
    </>
  );
}
