"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { RealEval } from "@/lib/types";
import { num, pct } from "@/lib/format";
import { TallyBar } from "./ui";

const REPORT_URL = "https://github.com/sritipeach1/netwatch-ids/blob/main/docs/cicids2017-results.md";

/** Shown only after the classifier has been evaluated on CIC-IDS2017 and the results committed. */
export function RealEvalPanel() {
  // Static results: fetch once, and stay hidden if they have not been generated (404).
  const [data, setData] = useState<RealEval | null>(null);
  useEffect(() => {
    api<RealEval>("/api/model/real-eval").then(setData).catch(() => setData(null));
  }, []);
  if (!data) return null;
  const cv = data.cross_validation;
  const d = cv.detection;
  const sim = data.simulator_model_on_real_data?.detection;
  const tiles = [
    { label: "Attacks detected", value: pct(d.recall), note: `${num(d.attack_windows)} attack windows` },
    { label: "False alarm rate", value: `${(d.false_alarm_rate * 100).toFixed(2)}%`, note: `${num(d.false_alarms)} of ${num(d.benign_windows)} benign windows` },
    { label: "Macro F1", value: cv.macro_f1.mean.toFixed(2), note: `±${cv.macro_f1.std.toFixed(2)} across ${data.method.folds} folds` },
    { label: "Real flows", value: num(data.data.flows), note: `${num(data.data.windows)} source windows` },
  ];

  return (
    <section aria-labelledby="real-eval" className="mt-5 rounded-2xl border border-rule bg-surface p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="real-eval" className="text-[17px] font-semibold tracking-[-0.01em]">Tested on real traffic: {data.dataset}</h2>
          <p className="max-w-[72ch] text-[13px] text-ink-3">
            The same 11 features, trained and scored on captured lab traffic. {data.method.folds}-fold cross-validation grouped by {data.method.grouping}, so every figure comes from windows the model did not train on.
          </p>
        </div>
        <a href={REPORT_URL} target="_blank" rel="noreferrer" className="rounded-lg border border-rule-strong px-3 py-1.5 text-[13px] font-semibold hover:bg-surface-2">
          Read the full report
        </a>
      </div>

      <div className="mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-rule bg-rule lg:grid-cols-4">
        {tiles.map((t) => (
          <div key={t.label} className="bg-surface px-4 py-3">
            <p className="text-[13px] text-ink-2">{t.label}</p>
            <p className="figure mt-1 text-[34px]">{t.value}</p>
            <p className="mt-1 text-[12px] text-ink-3">{t.note}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,320px)]">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[440px] text-left text-[14px]">
            <thead>
              <tr className="border-b border-rule-strong text-[12px] text-ink-3">
                <th className="py-2 pr-3 font-medium">Attack</th>
                <th className="py-2 pr-3 text-right font-medium">Windows</th>
                <th className="py-2 pr-3 font-medium">Detected</th>
                <th className="py-2 text-right font-medium">Right type</th>
              </tr>
            </thead>
            <tbody>
              {cv.by_attack.map((a) => (
                <tr key={a.attack} className="border-b border-rule last:border-b-0">
                  <td className="py-2 pr-3">{a.attack}</td>
                  <td className="py-2 pr-3 text-right text-ink-2">{num(a.windows)}</td>
                  <td className="py-2 pr-3">
                    <span className="flex items-center gap-3">
                      <TallyBar value={a.detected} max={1} color="var(--signal)" segments={20} />
                      <span className="w-12 text-right font-semibold">{pct(a.detected)}</span>
                    </span>
                  </td>
                  <td className="py-2 text-right">{pct(a.correct_type)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex flex-col gap-3 text-[13px] text-ink-2">
          {sim && (
            <p>
              <span className="font-semibold text-ink">Simulator model on real traffic.</span> The simulator-trained model this demo runs catches {pct(sim.recall)} of the same real attack windows, with a {(sim.false_alarm_rate * 100).toFixed(2)}% false alarm rate. Retrained on real traffic: {pct(d.recall)} and {(d.false_alarm_rate * 100).toFixed(2)}%.
            </p>
          )}
          <p>
            Web attacks, bots and infiltration ({num(data.data.excluded_other)} windows) are left to the signature rules, as in the live system.
          </p>
          <p>
            CIC-IDS2017 is a 2017 lab capture with known labelling errors, so treat these as benchmark figures, not a promise for any particular network.
          </p>
        </div>
      </div>
    </section>
  );
}
