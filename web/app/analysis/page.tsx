"use client";

import { useState } from "react";
import { Download } from "lucide-react";
import { useApi } from "@/lib/live";
import type { Compare } from "@/lib/types";
import { TRUTH_LABELS, num, pct } from "@/lib/format";
import { BarList } from "@/components/Charts";
import { Radar } from "@/components/Radar";
import { RealEvalPanel } from "@/components/RealEval";
import { ErrorNote, PageHeader, Panel, Skeleton } from "@/components/ui";

const RANGES = [6, 12, 24];
const DETECTORS = [
  { key: "signature", name: "Signature rules", color: "var(--rules)", dark: "var(--console-rules)" },
  { key: "ml", name: "Flow classifier", color: "var(--signal-strong)", dark: "var(--signal)" },
  { key: "hybrid", name: "Both together", color: "var(--ink)", dark: "var(--console-ink)" },
] as const;

function toCsv(d: Compare): string {
  const lines = ["detector,true_positives,false_positives,missed,precision,recall,f1"];
  for (const k of DETECTORS) {
    const s = d.detectors[k.key];
    lines.push([k.name, s.tp, s.fp, s.fn, s.precision, s.recall, s.f1].join(","));
  }
  lines.push("", "attack,episodes,signature_recall,classifier_recall,both_recall");
  for (const [t, v] of Object.entries(d.by_truth)) lines.push([TRUTH_LABELS[t] ?? t, v.episodes, v.signature, v.ml, v.hybrid].join(","));
  return lines.join("\n");
}

export default function Analysis() {
  const [hours, setHours] = useState(24);
  const { data, error, loading, reload } = useApi<Compare>(`/api/compare?hours=${hours}`, 30000);

  const exportCsv = () => {
    if (!data) return;
    const url = URL.createObjectURL(new Blob([toCsv(data)], { type: "text/csv" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `netwatch-detection-${hours}h.csv` });
    a.click();
    URL.revokeObjectURL(url);
  };

  const rec = (k: (typeof DETECTORS)[number]["key"]) => (data ? pct(data.detectors[k].recall) : "");
  const truths = data ? Object.entries(data.by_truth) : [];
  const m = data?.model;

  return (
    <>
      <PageHeader
        title="Detection analysis"
        note={data ? `${num(data.episodes)} labelled episodes` : undefined}
        description="How well signature rules, the flow classifier, and the two together separate attacks from normal traffic."
        actions={
          <>
            <div role="group" aria-label="Time range" className="flex rounded-lg border border-rule-strong bg-surface p-0.5">
              {RANGES.map((r) => (
                <button
                  key={r}
                  type="button"
                  aria-pressed={hours === r}
                  onClick={() => setHours(r)}
                  className={`rounded-md px-3 py-1.5 text-[13px] font-semibold ${hours === r ? "bg-ink text-surface" : "text-ink-2 hover:bg-surface-2 hover:text-ink"}`}
                >
                  {r} h
                </button>
              ))}
            </div>
            <button type="button" onClick={exportCsv} disabled={!data} className="flex items-center gap-1.5 rounded-lg border border-rule-strong bg-surface px-3 py-2 text-[13px] font-semibold hover:bg-surface-2 disabled:text-ink-3">
              <Download size={15} aria-hidden="true" />
              Export CSV
            </button>
          </>
        }
      />

      {error && !data ? (
        <ErrorNote message={error} onRetry={reload} />
      ) : loading && !data ? (
        <Skeleton h={320} />
      ) : data && data.episodes === 0 ? (
        <Panel title="No labelled traffic in this range" note="Scores need episodes with a known label, which the simulator provides.">
          <p className="text-ink-2">Pick a longer range or wait for the simulator to produce more traffic.</p>
        </Panel>
      ) : data ? (
        <>
          <p className="mb-5 max-w-[72ch] text-[17px] leading-relaxed">
            Across {num(data.episodes)} labelled episodes, signatures caught {rec("signature")} of attacks, the classifier caught {rec("ml")}, and together they caught {rec("hybrid")}. Each finds attacks the other misses. All of this is measured on simulated traffic.
          </p>

          <section aria-labelledby="by-attack" className="console mb-5 rounded-[20px] border border-console-line p-5 sm:p-6">
            <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
              <div>
                <h2 id="by-attack" className="text-[17px] font-semibold tracking-[-0.01em]">Which detector catches which attack</h2>
                <p className="text-[13px] text-console-dim">Share of episodes detected, by attack type</p>
              </div>
              <ul className="flex flex-wrap gap-x-4 gap-y-1 text-[13px] text-console-dim">
                {DETECTORS.map((d) => (
                  <li key={d.key} className="flex items-center gap-1.5">
                    <span aria-hidden="true" className="inline-block h-0 w-4 border-t-2" style={{ borderColor: d.dark, borderStyle: d.key === "hybrid" ? "dashed" : "solid" }} />
                    {d.name}
                  </li>
                ))}
              </ul>
            </div>
            <div className="grid items-center gap-6 lg:grid-cols-[minmax(0,480px)_minmax(0,1fr)]">
              <Radar
                axes={truths.map(([t]) => TRUTH_LABELS[t] ?? t)}
                series={DETECTORS.map((d) => ({
                  key: d.key,
                  name: d.name,
                  color: d.dark,
                  fill: d.key === "hybrid" ? 0 : 0.16,
                  dashed: d.key === "hybrid",
                  values: truths.map(([, v]) => v[d.key]),
                }))}
              />
              <div className="overflow-x-auto">
                <table className="w-full min-w-[460px] text-left text-[14px]">
                  <thead>
                    <tr className="border-b border-console-line text-[12px] text-console-dim">
                      <th className="py-2 pr-3 font-medium">Attack</th>
                      <th className="py-2 pr-3 text-right font-medium">Episodes</th>
                      {DETECTORS.map((d) => <th key={d.key} className="py-2 pl-3 text-right font-medium">{d.name}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {truths.map(([t, v]) => (
                      <tr key={t} className="border-b border-console-line last:border-b-0">
                        <td className="py-2.5 pr-3">{TRUTH_LABELS[t] ?? t}</td>
                        <td className="py-2.5 pr-3 text-right text-console-dim">{num(v.episodes)}</td>
                        {DETECTORS.map((d) => {
                          const val = v[d.key];
                          return (
                            <td key={d.key} className="py-2.5 pl-3 text-right">
                              <span className={val < 0.5 ? "font-semibold text-signal" : ""}>{pct(val)}</span>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="mt-3 text-[13px] text-console-dim">Orange marks attacks a detector mostly misses. The two detectors cover each other&apos;s gaps.</p>
              </div>
            </div>
          </section>

          <Panel title="Overall scores" note="An episode is one source's burst of activity, scored once per detector." className="mb-5">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-left text-[14px]">
                <thead>
                  <tr className="border-b border-rule-strong text-[12px] text-ink-3">
                    <th className="py-2 pr-3 font-medium">Detector</th>
                    <th className="py-2 pr-3 font-medium">Precision</th>
                    <th className="py-2 pr-3 font-medium">Recall</th>
                    <th className="py-2 pr-3 font-medium">F1</th>
                    <th className="py-2 pr-3 font-medium">False alarms</th>
                    <th className="py-2 font-medium">Missed attacks</th>
                  </tr>
                </thead>
                <tbody>
                  {DETECTORS.map((d) => {
                    const s = data.detectors[d.key];
                    return (
                      <tr key={d.key} className="border-b border-rule">
                        <td className="py-2.5 pr-3 font-medium"><span aria-hidden="true" className="mr-2 inline-block h-2.5 w-2.5 rounded-full align-middle" style={{ background: d.color }} />{d.name}</td>
                        <td className="py-2.5 pr-3">{pct(s.precision)}</td>
                        <td className="py-2.5 pr-3">{pct(s.recall)}</td>
                        <td className="py-2.5 pr-3">{s.f1.toFixed(2)}</td>
                        <td className="py-2.5 pr-3">{num(s.fp)}</td>
                        <td className="py-2.5">{num(s.fn)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p className="mt-3 max-w-[70ch] text-[13px] text-ink-3">
              Most false alarms come from an authorised internal scanner that behaves exactly like an attacker. Allowlisting its address range keeps it from being blocked.
            </p>
          </Panel>

          {m && (
            <div className="grid gap-5 lg:grid-cols-2">
              <Panel title="What the classifier looks at" note="Feature importance, share of the model's decisions">
                {m.feature_importance && (
                  <BarList
                    color="var(--signal)"
                    rows={Object.entries(m.feature_importance).slice(0, 7).map(([k, v]) => ({ label: k.replace(/^log_/, "").replace(/_/g, " "), value: v, display: pct(v) }))}
                  />
                )}
              </Panel>
              <Panel title="How it was trained" note="Held-out episodes, not seen during training">
                <p className="mb-3 text-ink-2">
                  A random forest trained on {num(m.windows ?? 0)} windows of {m.data ?? "simulated flows"}. Web attacks and DNS tunneling were left out on purpose, because they look like ordinary flows at this level.
                </p>
                {m.holdout && (
                  <table className="w-full text-left text-[14px]">
                    <thead><tr className="border-b border-rule-strong text-[12px] text-ink-3"><th className="py-1.5 font-semibold">Class</th><th className="py-1.5 font-semibold">Precision</th><th className="py-1.5 font-semibold">Recall</th></tr></thead>
                    <tbody>
                      {["benign", "scan", "bruteforce", "flood"].map((c) => m.holdout?.[c] && (
                        <tr key={c} className="border-b border-rule"><td className="py-1.5">{c}</td><td className="py-1.5">{pct(m.holdout[c].precision)}</td><td className="py-1.5">{pct(m.holdout[c].recall)}</td></tr>
                      ))}
                    </tbody>
                  </table>
                )}
                <p className="mt-3 text-[13px] text-ink-3">These numbers describe the simulator, not real networks. Results on real captured traffic are below, when they have been generated.</p>
              </Panel>
            </div>
          )}

          <RealEvalPanel />
        </>
      ) : null}
    </>
  );
}
