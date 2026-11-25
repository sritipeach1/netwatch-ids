export type Alert = {
  id: number;
  ts: number;
  source: "suricata" | "ml";
  sig_id: number | null;
  signature: string;
  category: string | null;
  attack_type: string;
  technique: string | null;
  severity: number;
  src_ip: string;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  proto: string | null;
  country: string | null;
  action: string;
  score: number | null;
};

export type Block = {
  id: number;
  ip: string;
  reason: string | null;
  attack_type: string | null;
  ts: number;
  expires: number;
  mode: string;
  latency: number | null;
};

export type Count = { key: string | number; count: number; label?: string };

export type Stats = {
  alerts: number;
  blocked: number;
  attackers: number;
  median_time_to_block: number | null;
  active_blocks: number;
  by_type: Count[];
  by_country: Count[];
  by_severity: Count[];
};

export type TimelinePoint = { t: number; detected: number; blocked: number };

export type DetectorScore = {
  tp: number; fp: number; fn: number; precision: number; recall: number; f1: number;
};

export type Compare = {
  episodes: number;
  detectors: Record<"signature" | "ml" | "hybrid", DetectorScore>;
  by_truth: Record<string, { episodes: number; signature: number; ml: number; hybrid: number }>;
  model: {
    windows?: number;
    episodes?: number;
    data?: string;
    holdout?: Record<string, Record<string, number>>;
    feature_importance?: Record<string, number>;
  } | null;
};

export type Health = {
  status: string;
  mode: "demo" | "live";
  response_mode: string;
  model_loaded: boolean;
  uptime_s: number;
};
