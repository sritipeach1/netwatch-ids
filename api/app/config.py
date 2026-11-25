"""Runtime settings, read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.getenv(name, default).split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    # demo: a simulated sensor generates EVE-style events. live: tail a real Suricata eve.json.
    mode: str = "demo"
    db_path: str = "netwatch.db"
    eve_path: str = "/var/log/suricata/eve.json"
    # off | dry-run | simulated | enforce  (enforce shells out to nftables)
    response_mode: str = "simulated"
    allowlist: tuple[str, ...] = ("127.0.0.0/8",)
    ml_threshold: float = 0.80
    ml_block_threshold: float = 0.90
    model_path: str = "models/flow_clf.joblib"
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    backfill_hours: int = 24
    live_attacks: bool = True


def get_settings() -> Settings:
    mode = os.getenv("NETWATCH_MODE", "demo")
    default_resp = "simulated" if mode == "demo" else "dry-run"
    return Settings(
        mode=mode,
        db_path=os.getenv("NETWATCH_DB", "netwatch.db"),
        eve_path=os.getenv("NETWATCH_EVE_PATH", "/var/log/suricata/eve.json"),
        response_mode=os.getenv("NETWATCH_RESPONSE", default_resp),
        allowlist=_csv("NETWATCH_ALLOWLIST", "127.0.0.0/8"),
        ml_threshold=float(os.getenv("NETWATCH_ML_THRESHOLD", "0.80")),
        ml_block_threshold=float(os.getenv("NETWATCH_ML_BLOCK_THRESHOLD", "0.90")),
        model_path=os.getenv("NETWATCH_MODEL", "models/flow_clf.joblib"),
        cors_origins=_csv("NETWATCH_CORS", "http://localhost:3000"),
        backfill_hours=int(os.getenv("NETWATCH_BACKFILL_HOURS", "24")),
        live_attacks=os.getenv("NETWATCH_LIVE_ATTACKS", "1") == "1",
    )
