"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { X, Crosshair, Check, Loader2 } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { ATTACK_CHOICES, clock, duration } from "@/lib/format";
import { useLive, useNow } from "@/lib/live";
import { SeverityBadge } from "./ui";

type Run = { kind: string; src_ip: string; startedAt: number };

export function SimulatePanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [kind, setKind] = useState<string>("scan");
  const [run, setRun] = useState<Run | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { alerts, blocksByIp } = useLive();
  const now = useNow(1000);
  const panel = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  const launchBtn = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement;
    panel.current?.focus();
    return () => { (opener.current as HTMLElement | null)?.focus?.(); };
  }, [open]);

  // Escape closes the panel even if focus has slipped out of it.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "Tab" || !panel.current) return;
    const f = panel.current.querySelectorAll<HTMLElement>("button:not([disabled]), input, [tabindex]:not([tabindex='-1'])");
    if (f.length === 0) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };

  const launch = async () => {
    setBusy(true); setError(null);
    try {
      const r = await api<{ kind: string; src_ip: string }>("/api/simulate", { method: "POST", body: JSON.stringify({ attack: kind }) });
      setRun({ kind: r.kind, src_ip: r.src_ip, startedAt: Date.now() / 1000 });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't reach the API. Try again.");
    } finally {
      setBusy(false);
      // The launch button is disabled while busy, which drops focus; put it back in the panel.
      requestAnimationFrame(() => { if (!panel.current?.contains(document.activeElement)) launchBtn.current?.focus(); });
    }
  };

  const related = useMemo(
    () => (run ? alerts.filter((a) => a.src_ip === run.src_ip).sort((a, b) => a.ts - b.ts) : []),
    [alerts, run],
  );
  const block = run ? blocksByIp[run.src_ip] : undefined;
  const waited = run ? now - run.startedAt : 0;
  const choice = ATTACK_CHOICES.find((c) => c.id === kind);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-[#151915]/45" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby="sim-title"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="slide-in flex h-full w-full max-w-[440px] flex-col overflow-y-auto border-l border-rule bg-surface p-6 shadow-[0_0_40px_rgba(21,25,21,0.25)]"
      >
        <div className="mb-1 flex items-start justify-between gap-4">
          <h2 id="sim-title" className="text-[24px] font-semibold leading-tight tracking-[-0.02em]">Simulate an attack</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="grid h-9 w-9 place-items-center rounded-lg text-ink-2 hover:bg-surface-2"><X size={20} /></button>
        </div>
        <p className="mb-4 text-ink-2">Starts traffic from a made-up address. It goes through the same detectors and response rules as real events.</p>

        <fieldset className="mb-4">
          <legend className="mb-2 text-[14px] font-semibold">Attack type</legend>
          <div className="flex flex-col gap-1.5">
            {ATTACK_CHOICES.map((c) => (
              <label key={c.id} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 ${kind === c.id ? "border-signal-strong bg-[#f3dccb]/60 shadow-[inset_0_0_0_1px_var(--signal-strong)]" : "border-rule hover:border-rule-strong"}`}>
                <input type="radio" name="attack" value={c.id} checked={kind === c.id} onChange={() => setKind(c.id)} className="mt-1 accent-[var(--signal-strong)]" />
                <span><span className="block font-semibold leading-snug">{c.label}</span><span className="block text-[13px] text-ink-2">{c.note}</span></span>
              </label>
            ))}
          </div>
        </fieldset>

        <button
          ref={launchBtn}
          type="button"
          onClick={launch}
          disabled={busy}
          className="flex items-center justify-center gap-2 rounded-lg bg-signal-strong px-4 py-3 font-semibold text-white hover:bg-[#b3470c] disabled:opacity-60"
        >
          {busy ? <Loader2 size={16} className="animate-spin" aria-hidden="true" /> : <Crosshair size={16} aria-hidden="true" />}
          Launch {choice?.label.replace(/^[A-Z](?=[a-z])/, (c) => c.toLowerCase())}
        </button>
        {error && <p role="alert" className="mt-2 text-[13px] text-ink-2">{error}</p>}

        {run && (
          <div className="mt-6 border-t border-rule pt-4" aria-live="polite">
            <h3 className="mb-2 font-semibold">Source <span className="addr">{run.src_ip}</span></h3>
            <ol className="flex flex-col gap-2 text-[14px]">
              <li className="flex gap-2"><Check size={16} className="mt-0.5 shrink-0" aria-hidden="true" />Traffic started</li>
              {related.map((a) => (
                <li key={a.id} className="flex flex-wrap items-center gap-2">
                  <Check size={16} className="shrink-0" aria-hidden="true" />
                  <span>{clock(a.ts)}</span><SeverityBadge severity={a.severity} /><span>{a.signature}</span>
                </li>
              ))}
              {block ? (
                <li className="flex gap-2 font-semibold"><Check size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
                  Blocked{block.latency != null ? ` ${duration(block.latency)} after the first packet` : ""}</li>
              ) : related.length > 0 && waited > 6 ? (
                <li className="flex gap-2 text-ink-2"><Check size={16} className="mt-0.5 shrink-0" aria-hidden="true" />Logged only. This one isn&apos;t blocked automatically.</li>
              ) : (
                <li className="flex gap-2 text-ink-2"><Loader2 size={16} className="mt-0.5 shrink-0 animate-spin" aria-hidden="true" />
                  {related.length === 0 && waited > 12 ? "Nothing raised yet. Slow attacks can take a minute." : "Watching for detections"}</li>
              )}
            </ol>
          </div>
        )}
      </div>
    </div>
  );
}
