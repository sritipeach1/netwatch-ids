"""Event pipeline: parse -> aggregate -> score -> alert -> respond -> publish."""
from __future__ import annotations

import asyncio
from typing import Optional

from . import attack_map, geo
from .config import Settings
from .db import Store
from .eve import AlertEvent, Flow, parse_event
from .ml import AnomalyModel, Episode, FlowAggregator
from .response import ResponseEngine

TICK_SECONDS = 5.0
CORROBORATION_WINDOW = 60.0


class Bus:
    """Fan-out of live events to SSE subscribers."""

    def __init__(self) -> None:
        self.queues: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self.queues.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.queues.discard(q)

    def publish(self, event: dict) -> None:
        for q in list(self.queues):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # a slow client just misses events


class Pipeline:
    def __init__(self, store: Store, response: ResponseEngine, model: Optional[AnomalyModel],
                 bus: Bus, settings: Settings) -> None:
        self.store, self.response, self.model, self.bus, self.cfg = store, response, model, bus, settings
        self.agg = FlowAggregator()
        self.dropped = 0  # events from sources that were already blocked
        self._last_tick = 0.0

    # ---- entry point ---------------------------------------------------
    def handle(self, raw: dict) -> None:
        ev = parse_event(raw)
        if ev is None:
            return
        self._tick(ev.ts)
        if self.response.is_blocked(ev.src_ip, ev.ts):
            # The sensor sits before the firewall, so it still sees this traffic. Detectors keep
            # scoring it (for the comparison) but no alerts are raised and nothing is stored.
            self.dropped += 1
            self._shadow(ev)
            return
        if isinstance(ev, Flow):
            self._on_flow(ev)
        else:
            self._on_alert(ev)

    def flush(self, now: float, force: bool = False) -> None:
        """Close episodes whose source went quiet. Called on a timer in live mode."""
        self._tick(now)
        for ep in self.agg.flush(now, force=force):
            self._close(ep)

    # ---- internals -----------------------------------------------------
    def _tick(self, now: float) -> None:
        if now - self._last_tick < TICK_SECONDS:
            return
        self._last_tick = now
        for b in self.response.expire(now):
            self.bus.publish({"type": "unblock", "data": {"ip": b["ip"], "ts": now}})

    def _shadow(self, ev) -> None:
        if isinstance(ev, Flow):
            ep, closed = self.agg.add_flow(ev)
            for c in closed:
                self._close(c)
            if self.model and self.agg.due(ep, ev.ts):
                self._score(ep, ev.ts, emit=False)
        else:
            _, closed = self.agg.touch_alert(ev.src_ip, ev.ts, ev.truth)
            for c in closed:
                self._close(c)

    def _on_flow(self, f: Flow) -> None:
        ep, closed = self.agg.add_flow(f)
        for c in closed:
            self._close(c)
        if self.model and self.agg.due(ep, f.ts):
            self._score(ep, f.ts, emit=True)

    def _on_alert(self, a: AlertEvent) -> None:
        ep, closed = self.agg.touch_alert(a.src_ip, a.ts, a.truth)
        for c in closed:
            self._close(c)
        attack_type, technique = attack_map.lookup_sid(a.sid)
        self._emit({
            "ts": a.ts, "source": "suricata", "sig_id": a.sid, "signature": a.signature,
            "category": a.category, "attack_type": attack_type, "technique": technique,
            "severity": a.severity, "src_ip": a.src_ip, "src_port": a.src_port, "dest_ip": a.dest_ip,
            "dest_port": a.dest_port, "proto": a.proto, "score": None, "truth": a.truth,
        }, ep)

    def _score(self, ep: Episode, now: float, emit: bool) -> None:
        label, score = self.model.predict(self.agg.features(ep))
        ep.new_since_eval, ep.last_eval = 0, now
        if label != "benign" and (ep.ml_label == "benign" or score > ep.ml_score):
            ep.ml_label, ep.ml_score = label, score
        elif ep.ml_label == "benign":
            ep.ml_score = max(ep.ml_score, score)
        if not emit or label == "benign" or ep.ml_alerted:
            return
        ep.ml_alerted = True
        attack_type, technique = attack_map.lookup_ml(label)
        last = ep.rows[-1] if ep.rows else (now, 0, 0, 0, 0, 0, 0)
        self._emit({
            "ts": now, "source": "ml", "sig_id": None,
            "signature": f"ML anomaly: {attack_map.ATTACK_LABELS.get(attack_type, label).lower()} behaviour",
            "category": "Anomalous flow behaviour", "attack_type": attack_type, "technique": technique,
            "severity": 2, "src_ip": ep.src_ip, "src_port": 0, "dest_ip": "", "dest_port": last[1],
            "proto": "TCP", "score": round(score, 3), "truth": ep.truth,
        }, ep)

    def _close(self, ep: Episode) -> None:
        # Final, offline scoring of whatever the window held, so the comparison sees the whole episode.
        if self.model and ep.rows and ep.flows_seen >= 3 and ep.new_since_eval > 0:
            self._score(ep, ep.last, emit=False)
        if ep.truth != "unknown":
            self.store.insert_detection({
                "ts": ep.last, "src_ip": ep.src_ip, "truth": ep.truth, "sig_hit": ep.sig_hit,
                "ml_label": ep.ml_label, "ml_score": round(ep.ml_score, 3),
            })

    def _emit(self, alert: dict, ep: Episode) -> None:
        alert["country"] = geo.lookup(alert["src_ip"])
        alert["action"] = "alert only"
        row = self.store.insert_alert(alert)
        should_block, reason = self._decide(row)
        if should_block:
            blk = self.response.block(row["src_ip"], reason, row["attack_type"], row["ts"], row["id"],
                                      max(row["ts"] - ep.start, 0.0))
            label = self.response.action_label
            if blk and label:
                row["action"] = label
                self.store.set_alert_action(row["id"], label)
                self.store.mark_blocked(row["src_ip"], row["ts"] - CORROBORATION_WINDOW, label)
                self.bus.publish({"type": "block", "data": blk})
        self.bus.publish({"type": "alert", "data": row})

    def _decide(self, alert: dict) -> tuple[bool, str]:
        src, now = alert["src_ip"], alert["ts"]
        recent = now - CORROBORATION_WINDOW
        if alert["source"] == "ml":
            if alert["score"] >= self.cfg.ml_block_threshold:
                return True, f"ML anomaly score {alert['score']:.2f}"
            if self.store.count_recent_alerts(src, recent, source="suricata") >= 1:
                return True, "ML anomaly corroborated by a signature"
            return False, ""
        if alert["severity"] == 1:
            return True, f"High-severity signature {alert['sig_id']}"
        if self.store.count_recent_alerts(src, recent, source="ml") >= 1:
            return True, "Signature corroborated by ML anomaly"
        if self.store.count_recent_alerts(src, recent) >= 3:
            return True, "Repeated alerts from one source"
        return False, ""
