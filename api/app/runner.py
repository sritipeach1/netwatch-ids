"""Drivers that feed the pipeline: the demo simulator (backfill + live) and the real eve.json tailer."""
from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

from . import simulator as sim
from .eve import parse_ts, tail_eve
from .pipeline import Pipeline


def backfill(pipeline: Pipeline, now: float, hours: int, seed: int = 42) -> int:
    """Replay `hours` of simulated history through the real pipeline, in timestamp order."""
    rng = random.Random(seed)
    events: list[tuple[float, dict]] = []
    for t0, is_attack, kind, src in sim.build_history(now, hours, rng):
        for ev in sim.make_episode(is_attack, kind, src, t0, rng):
            events.append((parse_ts(ev["timestamp"]), ev))
    events.sort(key=lambda x: x[0])
    last_flush = 0.0
    for ts, ev in events:
        if ts > now:
            continue
        pipeline.handle(ev)
        if ts - last_flush >= 5.0:
            pipeline.flush(ts)
            last_flush = ts
    pipeline.flush(now + 11.0)
    return len(events)


class DemoDriver:
    """Plays simulated traffic in real time and lets visitors launch attacks on demand."""

    def __init__(self, pipeline: Pipeline, live_attacks: bool = True, seed: Optional[int] = None) -> None:
        self.pipeline = pipeline
        self.live_attacks = live_attacks
        self.rng = random.Random(seed)
        self._last_launch = 0.0
        self._running = 0

    async def _play(self, events: list[dict]) -> None:
        timed = [(parse_ts(e["timestamp"]), e) for e in events]
        i = 0
        self._running += 1
        try:
            while i < len(timed):
                now = time.time()
                while i < len(timed) and timed[i][0] <= now:
                    self.pipeline.handle(timed[i][1])
                    i += 1
                if i < len(timed):
                    await asyncio.sleep(min(max(timed[i][0] - now, 0.02), 0.5))
        finally:
            self._running -= 1

    def launch(self, kind: str) -> dict:
        """Start one simulated attack from a fresh source address. Raises ValueError on bad input."""
        if kind not in sim.ATTACK_KINDS:
            raise ValueError(f"unknown attack: {kind}")
        now = time.time()
        if now - self._last_launch < 2.0 or self._running >= 12:
            raise RuntimeError("busy")
        self._last_launch = now
        for _ in range(10):
            src = sim.random_attacker(self.rng)
            if not self.pipeline.response.is_blocked(src, now):
                break
        asyncio.get_running_loop().create_task(self._play(sim.make_campaign(kind, src, now, self.rng)))
        return {"kind": kind, "src_ip": src}

    async def run(self) -> None:
        next_attack = time.time() + 6
        while True:
            now = time.time()
            if self.live_attacks and now >= next_attack:
                kind = sim.pick_kind(self.rng, True)
                asyncio.get_running_loop().create_task(
                    self._play(sim.make_campaign(kind, sim.random_attacker(self.rng), now, self.rng)))
                next_attack = now + self.rng.uniform(20, 45)
            kind = sim.pick_kind(self.rng, False)
            asyncio.get_running_loop().create_task(
                self._play(sim.make_benign(kind, sim.random_benign(self.rng, kind), now, self.rng)))
            await asyncio.sleep(self.rng.uniform(2.0, 5.0))

    async def flusher(self) -> None:
        while True:
            await asyncio.sleep(2.0)
            self.pipeline.flush(time.time())


async def run_live(pipeline: Pipeline, eve_path: str) -> None:
    async def flusher() -> None:
        while True:
            await asyncio.sleep(2.0)
            pipeline.flush(time.time())

    task = asyncio.create_task(flusher())
    try:
        async for raw in tail_eve(eve_path):
            pipeline.handle(raw)
    finally:
        task.cancel()
