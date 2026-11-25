"""Per-source behavioural features, attacker episodes, and the flow classifier wrapper."""
from __future__ import annotations

import json
import math
import os
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Optional

from .eve import Flow

WINDOW_SECONDS = 60.0
IDLE_SECONDS = 10.0  # a source silent for this long ends its episode
LABELS = ["benign", "scan", "bruteforce", "flood"]
FEATURES = [
    "log_flows", "log_flows_per_s", "log_unique_ports", "unique_port_ratio", "no_reply_ratio",
    "log_mean_bytes_out", "log_mean_bytes_in", "log_mean_pkts_out", "log_mean_duration",
    "top_port_share", "ssh_share",
]

Row = tuple  # (ts, dport, pkts_ts, pkts_tc, bytes_ts, bytes_tc, duration)


def window_features(rows: list[Row]) -> list[float]:
    n = len(rows)
    span = max(rows[-1][0] - rows[0][0], 1.0)
    ports = [r[1] for r in rows]
    uniq = len(set(ports))
    top_share = Counter(ports).most_common(1)[0][1] / n
    no_reply = sum(1 for r in rows if r[3] == 0) / n
    return [
        math.log1p(n),
        math.log1p(n / span),
        math.log1p(uniq),
        uniq / n,
        no_reply,
        math.log1p(sum(r[4] for r in rows) / n),
        math.log1p(sum(r[5] for r in rows) / n),
        math.log1p(sum(r[2] for r in rows) / n),
        math.log1p(sum(r[6] for r in rows) / n),
        top_share,
        sum(1 for p in ports if p == 22) / n,
    ]


@dataclass
class Episode:
    src_ip: str
    start: float
    last: float
    truth_votes: Counter = field(default_factory=Counter)
    sig_hit: bool = False
    ml_label: str = "benign"
    ml_score: float = 0.0
    rows: deque = field(default_factory=deque)
    new_since_eval: int = 0
    last_eval: float = 0.0
    flows_seen: int = 0
    ml_alerted: bool = False

    @property
    def truth(self) -> str:
        votes = {k: v for k, v in self.truth_votes.items() if k != "unknown"}
        if not votes:
            return "unknown"
        # an attack label wins over benign noise that shares the same source
        attack = {k: v for k, v in votes.items() if k != "benign"}
        return max((attack or votes).items(), key=lambda kv: kv[1])[0]


class FlowAggregator:
    """Tracks one open episode per source IP and exposes rolling-window features."""

    def __init__(self, window: float = WINDOW_SECONDS, idle: float = IDLE_SECONDS) -> None:
        self.window = window
        self.idle = idle
        self.open: dict[str, Episode] = {}

    def _new(self, src: str, ts: float) -> Episode:
        ep = Episode(src_ip=src, start=ts, last=ts, last_eval=ts)
        self.open[src] = ep
        return ep

    def add_flow(self, f: Flow) -> tuple[Episode, list[Episode]]:
        closed: list[Episode] = []
        ep = self.open.get(f.src_ip)
        if ep and f.ts - ep.last > self.idle:
            closed.append(self.open.pop(f.src_ip))
            ep = None
        if ep is None:
            ep = self._new(f.src_ip, f.ts)
        ep.last = max(ep.last, f.ts)
        ep.flows_seen += 1
        ep.new_since_eval += 1
        ep.truth_votes[f.truth] += 1
        ep.rows.append((f.ts, f.dest_port, f.pkts_ts, f.pkts_tc, f.bytes_ts, f.bytes_tc, f.duration))
        while ep.rows and ep.rows[0][0] < f.ts - self.window:
            ep.rows.popleft()
        return ep, closed

    def touch_alert(self, src: str, ts: float, truth: str) -> tuple[Episode, list[Episode]]:
        closed: list[Episode] = []
        ep = self.open.get(src)
        if ep and ts - ep.last > self.idle:
            closed.append(self.open.pop(src))
            ep = None
        if ep is None:
            ep = self._new(src, ts)
        ep.last = max(ep.last, ts)
        ep.sig_hit = True
        if truth != "unknown":
            ep.truth_votes[truth] += 1
        return ep, closed

    def due(self, ep: Episode, now: float) -> bool:
        if not ep.rows or ep.new_since_eval == 0:
            return False
        return ep.new_since_eval >= 25 or (ep.new_since_eval >= 3 and now - ep.last_eval >= 5.0)

    def features(self, ep: Episode) -> list[float]:
        return window_features(list(ep.rows))

    def flush(self, now: float, force: bool = False) -> list[Episode]:
        done = [src for src, ep in self.open.items() if force or now - ep.last > self.idle]
        return [self.open.pop(src) for src in done]


class AnomalyModel:
    def __init__(self, clf, classes: list[str], meta: dict, threshold: float) -> None:
        self.clf = clf
        self.classes = list(classes)
        self.meta = meta
        self.threshold = threshold
        self._benign = self.classes.index("benign")

    @classmethod
    def load(cls, path: str, threshold: float = 0.8) -> Optional["AnomalyModel"]:
        if not os.path.exists(path):
            return None
        import joblib

        bundle = joblib.load(path)
        meta_path = os.path.splitext(path)[0] + ".json"
        meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
        return cls(bundle["clf"], bundle["classes"], meta, threshold)

    def predict(self, feats: list[float]) -> tuple[str, float]:
        probs = self.clf.predict_proba([feats])[0]
        score = float(1.0 - probs[self._benign])
        if score < self.threshold:
            return "benign", score
        best = max((i for i in range(len(probs)) if i != self._benign), key=lambda i: probs[i])
        return self.classes[best], score
