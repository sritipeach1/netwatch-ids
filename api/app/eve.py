"""Parsing and tailing of Suricata EVE JSON."""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import AsyncIterator, Optional


@dataclass
class Flow:
    ts: float
    src_ip: str
    dest_ip: str
    dest_port: int
    proto: str
    pkts_ts: int
    pkts_tc: int
    bytes_ts: int
    bytes_tc: int
    duration: float
    truth: str


@dataclass
class AlertEvent:
    ts: float
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    sid: int
    signature: str
    category: str
    severity: int
    truth: str


def parse_ts(value: str) -> float:
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


def format_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def parse_event(ev: dict) -> Optional[Flow | AlertEvent]:
    """Turn one EVE record into a Flow or AlertEvent. Other event types are ignored."""
    kind = ev.get("event_type")
    if kind not in ("alert", "flow"):
        return None
    try:
        ts = parse_ts(ev["timestamp"])
        src_ip = ev["src_ip"]
        dest_ip = ev.get("dest_ip", "")
        dest_port = int(ev.get("dest_port") or 0)
        proto = str(ev.get("proto", "")).upper()
    except (KeyError, TypeError, ValueError):
        return None
    truth = (ev.get("netwatch") or {}).get("truth", "unknown")
    if kind == "alert":
        a = ev.get("alert") or {}
        return AlertEvent(
            ts=ts, src_ip=src_ip, src_port=int(ev.get("src_port") or 0), dest_ip=dest_ip,
            dest_port=dest_port, proto=proto, sid=int(a.get("signature_id", 0)),
            signature=str(a.get("signature", "unknown")), category=str(a.get("category", "")),
            severity=int(a.get("severity", 3)), truth=truth,
        )
    f = ev.get("flow") or {}
    return Flow(
        ts=ts, src_ip=src_ip, dest_ip=dest_ip, dest_port=dest_port, proto=proto,
        pkts_ts=int(f.get("pkts_toserver", 0)), pkts_tc=int(f.get("pkts_toclient", 0)),
        bytes_ts=int(f.get("bytes_toserver", 0)), bytes_tc=int(f.get("bytes_toclient", 0)),
        duration=float(f.get("age", 0)), truth=truth,
    )


async def tail_eve(path: str, poll: float = 0.5) -> AsyncIterator[dict]:
    """Follow an eve.json file, surviving log rotation. Yields parsed JSON objects."""
    inode = None
    fh = None
    try:
        while True:
            try:
                st = os.stat(path)
            except FileNotFoundError:
                await asyncio.sleep(poll)
                continue
            if fh is None or st.st_ino != inode:
                if fh:
                    fh.close()
                fh = open(path, "r", encoding="utf-8")
                inode = st.st_ino
                fh.seek(0, os.SEEK_END)
            line = fh.readline()
            if not line:
                if st.st_size < fh.tell():
                    fh.seek(0)
                await asyncio.sleep(poll)
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
    finally:
        if fh:
            fh.close()
