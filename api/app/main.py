"""FastAPI application: REST + server-sent events for the dashboard."""
from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import runner
from .attack_map import ATTACK_LABELS
from .config import Settings, get_settings
from .db import Store
from .ml import AnomalyModel
from .pipeline import Bus, Pipeline
from .response import ResponseEngine


class SimulateRequest(BaseModel):
    attack: str


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or get_settings()
    store = Store(cfg.db_path)
    response = ResponseEngine(store, cfg.response_mode, cfg.allowlist)
    model = AnomalyModel.load(cfg.model_path, cfg.ml_threshold)
    bus = Bus()
    pipeline = Pipeline(store, response, model, bus, cfg)
    driver = runner.DemoDriver(pipeline, cfg.live_attacks)
    started = time.time()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks: list[asyncio.Task] = []
        if cfg.mode == "demo":
            if store.is_empty() and cfg.backfill_hours > 0:
                await asyncio.get_running_loop().run_in_executor(
                    None, runner.backfill, pipeline, time.time(), cfg.backfill_hours)
            tasks += [asyncio.create_task(driver.run()), asyncio.create_task(driver.flusher())]
        elif cfg.mode == "live":
            tasks.append(asyncio.create_task(runner.run_live(pipeline, cfg.eve_path)))
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(title="NetWatch IDS", version="1.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=list(cfg.cors_origins),
        allow_origin_regex=os.getenv("NETWATCH_CORS_REGEX") or None,
        allow_methods=["GET", "POST"], allow_headers=["*"],
    )
    app.state.store, app.state.pipeline, app.state.response = store, pipeline, response

    def require_write(x_api_key: Optional[str] = Header(default=None)) -> None:
        """Demo mode is open (everything is simulated). Live mode needs NETWATCH_API_KEY."""
        if cfg.mode == "demo":
            return
        key = os.getenv("NETWATCH_API_KEY")
        if not key or x_api_key != key:
            raise HTTPException(status_code=403, detail="API key required")

    def window(hours: int) -> tuple[float, float]:
        now = time.time()
        return now - hours * 3600.0, now

    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": cfg.mode, "response_mode": cfg.response_mode,
                "model_loaded": model is not None, "uptime_s": round(time.time() - started)}

    @app.get("/api/stats")
    def stats(hours: int = Query(24, ge=1, le=168)):
        since, now = window(hours)
        out = store.stats(since, now)
        for row in out["by_type"]:
            row["label"] = ATTACK_LABELS.get(row["key"], row["key"])
        return out

    @app.get("/api/timeline")
    def timeline(hours: int = Query(24, ge=1, le=168)):
        since, now = window(hours)
        return store.timeline(since, now)

    @app.get("/api/alerts")
    def alerts(limit: int = Query(50, ge=1, le=500), attack_type: Optional[str] = None,
               action: Optional[str] = Query(None, pattern="^(blocked|alert only)$")):
        return store.recent_alerts(limit, attack_type, action)

    @app.get("/api/blocks")
    def blocks():
        return store.active_blocks(time.time())

    @app.post("/api/blocks/{ip}/unblock", dependencies=[Depends(require_write)])
    def unblock(ip: str):
        if not response.unblock(ip):
            raise HTTPException(status_code=404, detail="No active block for that address")
        bus.publish({"type": "unblock", "data": {"ip": ip, "ts": time.time()}})
        return {"ok": True}

    @app.get("/api/compare")
    def compare(hours: int = Query(24, ge=1, le=168)):
        since, _ = window(hours)
        out = store.compare(since)
        out["model"] = model.meta if model else None
        return out

    @app.post("/api/simulate")
    async def simulate(req: SimulateRequest):
        if cfg.mode != "demo":
            raise HTTPException(status_code=404, detail="Simulation is only available in demo mode")
        try:
            return driver.launch(req.attack)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        except RuntimeError:
            raise HTTPException(status_code=429, detail="Another attack is still running. Try again in a moment.")

    @app.get("/api/stream")
    async def stream(request: Request):
        q = bus.subscribe()

        async def gen():
            try:
                yield "retry: 3000\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"event: {ev['type']}\ndata: {json.dumps(ev['data'])}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                bus.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


app = create_app()
