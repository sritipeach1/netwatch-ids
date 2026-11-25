"""SQLite storage for alerts, blocks, and per-episode detection results."""
from __future__ import annotations

import sqlite3
import statistics
import threading
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, source TEXT NOT NULL, sig_id INTEGER, signature TEXT NOT NULL,
  category TEXT, attack_type TEXT NOT NULL, technique TEXT, severity INTEGER NOT NULL,
  src_ip TEXT NOT NULL, src_port INTEGER, dest_ip TEXT, dest_port INTEGER, proto TEXT,
  country TEXT, action TEXT NOT NULL DEFAULT 'alert only', score REAL, truth TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip, ts);
CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL, reason TEXT, attack_type TEXT, ts REAL NOT NULL, expires REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, mode TEXT NOT NULL, latency REAL, alert_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip, active);
CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(ts);
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, src_ip TEXT NOT NULL, truth TEXT NOT NULL,
  sig_hit INTEGER NOT NULL, ml_label TEXT NOT NULL, ml_score REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_det_ts ON detections(ts);
"""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)

    # ---- helpers -------------------------------------------------------
    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def _one(self, sql: str, args: tuple = ()) -> Optional[dict]:
        rows = self._all(sql, args)
        return rows[0] if rows else None

    def _exec(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.lastrowid or 0

    def is_empty(self) -> bool:
        return (self._one("SELECT COUNT(*) AS n FROM alerts") or {"n": 0})["n"] == 0

    def reset(self) -> None:
        with self._lock:
            for t in ("alerts", "blocks", "detections"):
                self._db.execute(f"DELETE FROM {t}")
            self._db.commit()

    # ---- alerts --------------------------------------------------------
    def insert_alert(self, a: dict[str, Any]) -> dict:
        cols = ("ts", "source", "sig_id", "signature", "category", "attack_type", "technique",
                "severity", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "country",
                "action", "score", "truth")
        row = {c: a.get(c) for c in cols}
        row["action"] = row["action"] or "alert only"
        sql = f"INSERT INTO alerts ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        row["id"] = self._exec(sql, tuple(row[c] for c in cols))
        return row

    def set_alert_action(self, alert_id: int, action: str) -> None:
        self._exec("UPDATE alerts SET action=? WHERE id=?", (action, alert_id))

    def count_recent_alerts(self, src_ip: str, since: float, source: Optional[str] = None) -> int:
        sql, args = "SELECT COUNT(*) AS n FROM alerts WHERE src_ip=? AND ts>=?", [src_ip, since]
        if source:
            sql += " AND source=?"; args.append(source)
        r = self._one(sql, tuple(args))
        return r["n"] if r else 0

    def mark_blocked(self, src_ip: str, since: float, action: str) -> None:
        self._exec("UPDATE alerts SET action=? WHERE src_ip=? AND ts>=? AND action='alert only'",
                   (action, src_ip, since))

    def recent_alerts(self, limit: int = 50, attack_type: Optional[str] = None,
                      action: Optional[str] = None) -> list[dict]:
        where, args = [], []
        if attack_type:
            where.append("attack_type=?"); args.append(attack_type)
        if action == "blocked":
            where.append("action LIKE '%block%'")
        elif action == "alert only":
            where.append("action='alert only'")
        sql = "SELECT * FROM alerts"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        return self._all(sql, tuple(args) + (limit,))

    # ---- blocks --------------------------------------------------------
    def insert_block(self, b: dict[str, Any]) -> dict:
        cols = ("ip", "reason", "attack_type", "ts", "expires", "mode", "latency", "alert_id")
        row = {c: b.get(c) for c in cols}
        row["active"] = 1
        sql = f"INSERT INTO blocks ({','.join(cols)},active) VALUES ({','.join('?' * len(cols))},1)"
        row["id"] = self._exec(sql, tuple(row[c] for c in cols))
        return row

    def active_block(self, ip: str, now: float) -> Optional[dict]:
        return self._one("SELECT * FROM blocks WHERE ip=? AND active=1 AND expires>? "
                         "ORDER BY ts DESC LIMIT 1", (ip, now))

    def block_count(self, ip: str) -> int:
        return (self._one("SELECT COUNT(*) AS n FROM blocks WHERE ip=?", (ip,)) or {"n": 0})["n"]

    def active_blocks(self, now: float) -> list[dict]:
        return self._all("SELECT * FROM blocks WHERE active=1 AND expires>? ORDER BY ts DESC", (now,))

    def expire_blocks(self, now: float) -> list[dict]:
        rows = self._all("SELECT * FROM blocks WHERE active=1 AND expires<=?", (now,))
        if rows:
            self._exec("UPDATE blocks SET active=0 WHERE active=1 AND expires<=?", (now,))
        return rows

    def deactivate_block(self, ip: str) -> int:
        with self._lock:
            cur = self._db.execute("UPDATE blocks SET active=0 WHERE ip=? AND active=1", (ip,))
            self._db.commit()
            return cur.rowcount

    # ---- detections (one row per attacker episode, used for the comparison) ----
    def insert_detection(self, d: dict[str, Any]) -> None:
        self._exec("INSERT INTO detections (ts,src_ip,truth,sig_hit,ml_label,ml_score) VALUES (?,?,?,?,?,?)",
                   (d["ts"], d["src_ip"], d["truth"], int(d["sig_hit"]), d["ml_label"], d["ml_score"]))

    # ---- aggregates ----------------------------------------------------
    def stats(self, since: float, now: float) -> dict:
        n_alerts = (self._one("SELECT COUNT(*) AS n FROM alerts WHERE ts>=?", (since,)) or {"n": 0})["n"]
        n_blocks = (self._one("SELECT COUNT(*) AS n FROM blocks WHERE ts>=?", (since,)) or {"n": 0})["n"]
        attackers = (self._one("SELECT COUNT(DISTINCT src_ip) AS n FROM alerts WHERE ts>=?", (since,)) or {"n": 0})["n"]
        lat = [r["latency"] for r in self._all(
            "SELECT latency FROM blocks WHERE ts>=? AND latency IS NOT NULL", (since,))]
        by_type = self._all("SELECT attack_type AS key, COUNT(*) AS count FROM alerts WHERE ts>=? "
                            "GROUP BY attack_type ORDER BY count DESC", (since,))
        by_country = self._all("SELECT COALESCE(country,'Unknown') AS key, COUNT(*) AS count FROM alerts "
                               "WHERE ts>=? GROUP BY country ORDER BY count DESC", (since,))
        by_sev = self._all("SELECT severity AS key, COUNT(*) AS count FROM alerts WHERE ts>=? "
                           "GROUP BY severity", (since,))
        return {
            "alerts": n_alerts,
            "blocked": n_blocks,
            "attackers": attackers,
            "median_time_to_block": round(statistics.median(lat), 2) if lat else None,
            "active_blocks": len(self.active_blocks(now)),
            "by_type": by_type,
            "by_country": by_country,
            "by_severity": by_sev,
        }

    def timeline(self, since: float, now: float, bucket: float = 3600.0) -> list[dict]:
        start = int(since // bucket)
        end = int(now // bucket)
        out = {i: {"t": i * bucket, "detected": 0, "blocked": 0} for i in range(start, end + 1)}
        for r in self._all("SELECT CAST(ts/? AS INTEGER) AS b, COUNT(*) AS n FROM alerts WHERE ts>=? GROUP BY b",
                           (bucket, since)):
            if r["b"] in out:
                out[r["b"]]["detected"] = r["n"]
        for r in self._all("SELECT CAST(ts/? AS INTEGER) AS b, COUNT(*) AS n FROM blocks WHERE ts>=? GROUP BY b",
                           (bucket, since)):
            if r["b"] in out:
                out[r["b"]]["blocked"] = r["n"]
        return [out[k] for k in sorted(out)]

    def compare(self, since: float) -> dict:
        """Precision / recall of signature-only, ML-only and hybrid detection over labelled episodes."""
        rows = self._all("SELECT truth, sig_hit, ml_label FROM detections WHERE ts>=?", (since,))
        rows = [r for r in rows if r["truth"] != "unknown"]
        detectors = {
            "signature": lambda r: bool(r["sig_hit"]),
            "ml": lambda r: r["ml_label"] != "benign",
            "hybrid": lambda r: bool(r["sig_hit"]) or r["ml_label"] != "benign",
        }
        out: dict[str, Any] = {"episodes": len(rows), "detectors": {}, "by_truth": {}}
        for name, fn in detectors.items():
            tp = sum(1 for r in rows if r["truth"] != "benign" and fn(r))
            fp = sum(1 for r in rows if r["truth"] == "benign" and fn(r))
            fn_ = sum(1 for r in rows if r["truth"] != "benign" and not fn(r))
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn_) if tp + fn_ else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            out["detectors"][name] = {"tp": tp, "fp": fp, "fn": fn_, "precision": round(prec, 3),
                                      "recall": round(rec, 3), "f1": round(f1, 3)}
        truths = sorted({r["truth"] for r in rows if r["truth"] != "benign"})
        for t in truths:
            sub = [r for r in rows if r["truth"] == t]
            out["by_truth"][t] = {
                "episodes": len(sub),
                **{name: round(sum(1 for r in sub if fn(r)) / len(sub), 3) for name, fn in detectors.items()},
            }
        return out
