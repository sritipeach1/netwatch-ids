"use client";

import type { Alert } from "@/lib/types";
import { attackLabel, clock, relTime } from "@/lib/format";
import { ActionPill, SeverityBadge } from "./ui";

export function AlertsTable({ rows, fresh, now, compact = false }: { rows: Alert[]; fresh?: Set<number>; now: number; compact?: boolean }) {
  const th = "py-2.5 pr-4 text-[12px] font-medium text-ink-3";
  return (
    <div className="relative -mx-5 overflow-x-auto px-5">
      <table className="w-full min-w-[720px] text-left text-[14px]">
        <thead>
          <tr className="border-b border-rule-strong">
            <th className={th}>Time</th>
            <th className={th}>Source</th>
            <th className={th}>Detection</th>
            <th className={th}>Severity</th>
            {!compact && <th className={th}>ATT&amp;CK</th>}
            <th className="py-2.5 text-[12px] font-medium text-ink-3">Response</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id} className={`border-b border-rule align-top last:border-b-0 hover:bg-surface-2/60 ${fresh?.has(a.id) ? "fresh-row" : ""}`}>
              <td className="py-3 pr-4 whitespace-nowrap">
                <div>{relTime(a.ts, now)}</div>
                <div className="text-[12px] text-ink-3">{clock(a.ts)}</div>
              </td>
              <td className="py-3 pr-4 whitespace-nowrap">
                <div className="addr font-medium">{a.src_ip}</div>
                <div className="text-[12px] text-ink-3">{a.country ?? "Unknown"}</div>
              </td>
              <td className="py-3 pr-4">
                <div>
                  {attackLabel(a.attack_type)}
                  {a.dest_port ? <span className="addr ml-1.5 text-ink-3">:{a.dest_port}</span> : null}
                </div>
                <div className="text-[12px] text-ink-3">
                  {a.source === "ml" ? `Flow classifier, score ${a.score?.toFixed(2)}` : `Signature ${a.sig_id}`}
                </div>
              </td>
              <td className="py-3 pr-4"><SeverityBadge severity={a.severity} /></td>
              {!compact && <td className="addr py-3 pr-4 text-ink-2">{a.technique || "None"}</td>}
              <td className="py-3"><ActionPill action={a.action} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
