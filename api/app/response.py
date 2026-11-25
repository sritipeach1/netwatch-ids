"""Automated response: decide whether to block a source, apply the block, and expire it."""
from __future__ import annotations

import ipaddress
import subprocess
from typing import Callable, Optional

from .db import Store

FIRST_BLOCK_SECONDS = 3600.0
REPEAT_BLOCK_SECONDS = 24 * 3600.0
NFT_TABLE = ("inet", "netwatch", "blocklist")


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, timeout=5, capture_output=True)


class ResponseEngine:
    """
    Modes:
      off        never block
      dry-run    record what would be blocked, touch nothing
      simulated  record blocks as if enforced (used by the demo sensor)
      enforce    add the address to an nftables set with a timeout
    """

    def __init__(self, store: Store, mode: str = "dry-run", allowlist: tuple[str, ...] = (),
                 runner: Callable[[list[str]], None] = _run) -> None:
        if mode not in ("off", "dry-run", "simulated", "enforce"):
            raise ValueError(f"unknown response mode: {mode}")
        self.store = store
        self.mode = mode
        self.runner = runner
        self.networks = [ipaddress.ip_network(c, strict=False) for c in allowlist]

    def is_allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # never act on something we cannot parse
        return any(addr in n for n in self.networks)

    def is_blocked(self, ip: str, now: float) -> bool:
        return self.mode in ("simulated", "enforce") and self.store.active_block(ip, now) is not None

    @property
    def action_label(self) -> Optional[str]:
        return {"simulated": "blocked", "enforce": "blocked", "dry-run": "dry-run block"}.get(self.mode)

    def block(self, ip: str, reason: str, attack_type: str, now: float, alert_id: Optional[int],
              latency: Optional[float]) -> Optional[dict]:
        """Returns the new block row, or None when nothing was done."""
        if self.mode == "off" or self.is_allowlisted(ip):
            return None
        if self.store.active_block(ip, now):
            return None
        seconds = REPEAT_BLOCK_SECONDS if self.store.block_count(ip) >= 1 else FIRST_BLOCK_SECONDS
        if self.mode == "enforce":
            self.runner(["nft", "add", "element", *NFT_TABLE, "{", f"{ip} timeout {int(seconds)}s", "}"])
        return self.store.insert_block({
            "ip": ip, "reason": reason, "attack_type": attack_type, "ts": now,
            "expires": now + seconds, "mode": self.mode, "latency": latency, "alert_id": alert_id,
        })

    def unblock(self, ip: str) -> bool:
        changed = self.store.deactivate_block(ip) > 0
        if changed and self.mode == "enforce":
            try:
                self.runner(["nft", "delete", "element", *NFT_TABLE, "{", ip, "}"])
            except Exception:
                pass  # the nft element may already have timed out
        return changed

    def expire(self, now: float) -> list[dict]:
        return self.store.expire_blocks(now)
