"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { api, API_URL } from "./api";
import type { Alert, Block, Health } from "./types";

type State = { alerts: Alert[]; fresh: Set<number>; blocksByIp: Record<string, Block>; revision: number };
type Action =
  | { type: "seed"; alerts: Alert[] }
  | { type: "alert"; alert: Alert }
  | { type: "block"; block: Block }
  | { type: "unblock"; ip: string }
  | { type: "settled"; ids: number[] };

const MAX_ALERTS = 300;

function reducer(s: State, a: Action): State {
  switch (a.type) {
    case "seed":
      return { ...s, alerts: a.alerts };
    case "alert": {
      if (s.alerts.some((x) => x.id === a.alert.id)) return s;
      const fresh = new Set(s.fresh);
      fresh.add(a.alert.id);
      return { ...s, alerts: [a.alert, ...s.alerts].slice(0, MAX_ALERTS), fresh, revision: s.revision + 1 };
    }
    case "block": {
      const label = a.block.mode === "dry-run" ? "dry-run block" : "blocked";
      const alerts = s.alerts.map((x) =>
        x.src_ip === a.block.ip && x.action === "alert only" && a.block.ts - x.ts < 60 ? { ...x, action: label } : x,
      );
      return { ...s, alerts, blocksByIp: { ...s.blocksByIp, [a.block.ip]: a.block }, revision: s.revision + 1 };
    }
    case "unblock": {
      const { [a.ip]: _gone, ...rest } = s.blocksByIp;
      return { ...s, blocksByIp: rest, revision: s.revision + 1 };
    }
    case "settled": {
      const fresh = new Set(s.fresh);
      a.ids.forEach((id) => fresh.delete(id));
      return { ...s, fresh };
    }
  }
}

type Live = {
  alerts: Alert[];
  fresh: Set<number>;
  blocksByIp: Record<string, Block>;
  revision: number;
  connected: boolean;
  health: Health | null;
  error: boolean;
};

const Ctx = createContext<Live | null>(null);

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, { alerts: [], fresh: new Set<number>(), blocksByIp: {}, revision: 0 });
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api<Health>("/api/health"), api<Alert[]>("/api/alerts?limit=300")])
      .then(([h, a]) => {
        if (cancelled) return;
        setHealth(h);
        dispatch({ type: "seed", alerts: a });
      })
      .catch(() => !cancelled && setError(true));

    const es = new EventSource(`${API_URL}/api/stream`);
    es.onopen = () => { setConnected(true); setError(false); };
    es.onerror = () => setConnected(false);
    es.addEventListener("alert", (e) => dispatch({ type: "alert", alert: JSON.parse((e as MessageEvent).data) }));
    es.addEventListener("block", (e) => dispatch({ type: "block", block: JSON.parse((e as MessageEvent).data) }));
    es.addEventListener("unblock", (e) => dispatch({ type: "unblock", ip: JSON.parse((e as MessageEvent).data).ip }));
    return () => { cancelled = true; es.close(); };
  }, []);

  // New rows stay highlighted for a moment, then settle.
  useEffect(() => {
    if (state.fresh.size === 0) return;
    const ids = Array.from(state.fresh);
    const t = setTimeout(() => dispatch({ type: "settled", ids }), 2500);
    return () => clearTimeout(t);
  }, [state.fresh]);

  const value = useMemo<Live>(
    () => ({ ...state, connected, health, error }),
    [state, connected, health, error],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLive(): Live {
  const v = useContext(Ctx);
  if (!v) throw new Error("useLive must be used inside LiveProvider");
  return v;
}

/** Fetch a path now, then again every `intervalMs` and shortly after live events arrive. */
export function useApi<T>(path: string, intervalMs = 15000) {
  const { revision } = useLive();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);

  const load = useCallback(async () => {
    const mine = ++seq.current;
    try {
      const d = await api<T>(path);
      if (mine === seq.current) { setData(d); setError(null); }
    } catch (e) {
      if (mine === seq.current) setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      if (mine === seq.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => { setLoading(true); load(); }, [load]);
  useEffect(() => { const id = setInterval(load, intervalMs); return () => clearInterval(id); }, [load, intervalMs]);
  useEffect(() => {
    if (revision === 0) return;
    const t = setTimeout(load, 800);
    return () => clearTimeout(t);
  }, [revision, load]);

  return { data, error, loading, reload: load };
}

/** Re-renders on an interval so relative times stay current. */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => { const id = setInterval(() => setNow(Date.now() / 1000), intervalMs); return () => clearInterval(id); }, [intervalMs]);
  return now;
}
