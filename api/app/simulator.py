"""
Simulated sensor for demo mode.

It emits EVE-style flow and alert records for benign traffic and six attack campaigns, so the whole
pipeline (parser, aggregator, classifier, response engine, dashboard) runs without a live network.
Alerts follow the thresholds of the rules in suricata/rules/local.rules.
"""
from __future__ import annotations

import math
import random
from typing import Optional

from .eve import format_ts

VICTIMS = ["10.0.1.10", "10.0.1.20", "10.0.1.30"]
ATTACK_KINDS = ["scan", "slow_scan", "bruteforce", "flood", "web_attack", "dns_tunnel"]
BENIGN_KINDS = ["web_user", "crawler", "admin_ssh", "monitor", "dns_client", "misconfigured",
                "p2p", "page_load", "uptime_probe", "iot_chatty", "internal_scanner"]
ATTACK_WEIGHTS = [0.28, 0.12, 0.22, 0.06, 0.20, 0.12]
BENIGN_WEIGHTS = [0.26, 0.06, 0.05, 0.06, 0.15, 0.06, 0.08, 0.09, 0.08, 0.08, 0.03]

# truth label used for scoring each kind
TRUTH = {"scan": "scan", "slow_scan": "scan", "bruteforce": "bruteforce", "flood": "flood",
         "web_attack": "web_attack", "dns_tunnel": "dns_tunnel"}

SIGNATURES = {
    1000001: ("NETWATCH Port scan (SYN threshold)", "Attempted Information Leak", 2),
    1000002: ("NETWATCH SSH brute force attempt", "Attempted User Privilege Gain", 1),
    1000003: ("NETWATCH SQL injection in HTTP request", "Web Application Attack", 1),
    1000004: ("NETWATCH Suspicious DNS query length", "Potentially Bad Traffic", 2),
    1000005: ("NETWATCH SYN flood", "Attempted Denial of Service", 1),
}


def _flow(ts, src, dst, dport, proto, pts, ptc, bts, btc, age, truth, rng):
    return {
        "timestamp": format_ts(ts), "event_type": "flow", "src_ip": src,
        "src_port": rng.randint(32768, 60999), "dest_ip": dst, "dest_port": dport, "proto": proto,
        "flow": {"pkts_toserver": pts, "pkts_toclient": ptc, "bytes_toserver": bts,
                 "bytes_toclient": btc, "age": round(age, 3), "state": "closed"},
        "netwatch": {"truth": truth},
    }


def _alert(ts, src, dst, dport, proto, sid, truth, rng):
    sig, cat, sev = SIGNATURES[sid]
    return {
        "timestamp": format_ts(ts), "event_type": "alert", "src_ip": src,
        "src_port": rng.randint(32768, 60999), "dest_ip": dst, "dest_port": dport, "proto": proto,
        "alert": {"signature_id": sid, "signature": sig, "category": cat, "severity": sev},
        "netwatch": {"truth": truth},
    }


def random_attacker(rng: random.Random) -> str:
    return f"198.18.{rng.randint(10, 19)}.{rng.randint(1, 254)}"


def random_benign(rng: random.Random, kind: str = "") -> str:
    if kind == "internal_scanner":
        return f"10.0.2.{rng.randint(2, 40)}"
    return f"100.64.{rng.randint(0, 31)}.{rng.randint(1, 254)}"


def make_campaign(kind: str, src: str, t0: float, rng: random.Random) -> list[dict]:
    victim = rng.choice(VICTIMS)
    truth = TRUTH[kind]
    ev: list[dict] = []
    t = t0
    if kind in ("scan", "slow_scan"):
        n = rng.randint(80, 220) if kind == "scan" else rng.randint(35, 60)
        evasive = rng.random() < 0.35  # padded probes and many open ports blur the picture
        reply_rate = rng.uniform(0.2, 0.7) if evasive else rng.uniform(0.03, 0.45)
        for i, port in enumerate(rng.sample(range(1, 10000), n)):
            t += rng.uniform(0.01, 0.04) if kind == "scan" else rng.uniform(1.2, 2.0)
            replied = rng.random() < reply_rate
            if evasive:
                f = (rng.randint(1, 8), rng.randint(1, 6) if replied else 0, rng.randint(60, 1500),
                     rng.randint(60, 1200) if replied else 0, rng.uniform(0, 3))
            else:
                f = (rng.randint(1, 3), rng.randint(1, 2) if replied else 0, rng.randint(54, 200),
                     rng.randint(60, 140) if replied else 0, rng.uniform(0, 0.4))
            ev.append(_flow(t, src, victim, port, "TCP", *f, truth, rng))
            if kind == "scan" and i == 19:
                ev.append(_alert(t + 0.001, src, victim, port, "TCP", 1000001, truth, rng))
    elif kind == "bruteforce":
        port = rng.choice([22, 22, 22, 21, 3389, 5900])  # the SSH rule only covers port 22
        evasive = rng.random() < 0.35
        for i in range(rng.randint(8, 40)):
            t += rng.uniform(0.3, 1.5)
            if evasive:
                f = (rng.randint(3, 20), rng.randint(3, 20), rng.randint(200, 3000), rng.randint(200, 3500),
                     rng.uniform(0.1, 3))
            else:
                f = (rng.randint(8, 16), rng.randint(7, 15), rng.randint(900, 2200), rng.randint(1000, 2800),
                     rng.uniform(0.3, 2.0))
            ev.append(_flow(t, src, victim, port, "TCP", *f, truth, rng))
            if i == 5 and port == 22:
                ev.append(_alert(t + 0.001, src, victim, 22, "TCP", 1000002, truth, rng))
    elif kind == "flood":
        port = rng.choice([80, 443])
        evasive = rng.random() < 0.30
        gap = rng.uniform(0.003, 0.08) if evasive else rng.uniform(0.003, 0.03)
        reply_rate = rng.uniform(0.0, 0.6) if evasive else rng.uniform(0.0, 0.25)
        for i in range(rng.randint(150, 400)):
            t += gap * rng.uniform(0.5, 1.5)
            replied = rng.random() < reply_rate
            if evasive:
                f = (rng.randint(1, 6), 1 if replied else 0, rng.randint(54, 600), 60 if replied else 0,
                     rng.uniform(0.0, 0.5))
            else:
                f = (rng.randint(1, 3), 1 if replied else 0, rng.randint(54, 90), 60 if replied else 0,
                     rng.uniform(0.0, 0.05))
            ev.append(_flow(t, src, victim, port, "TCP", *f, truth, rng))
            if i == 19:
                ev.append(_alert(t + 0.001, src, victim, port, "TCP", 1000005, truth, rng))
    elif kind == "web_attack":
        port = rng.choice([80, 8080])
        for i in range(rng.randint(3, 7)):
            t += rng.uniform(0.8, 2.0)
            ev.append(_flow(t, src, victim, port, "TCP", rng.randint(6, 12), rng.randint(6, 12),
                            rng.randint(700, 2800), rng.randint(600, 7000), rng.uniform(0.2, 1.0), truth, rng))
            if i == 1:
                ev.append(_alert(t + 0.001, src, victim, port, "TCP", 1000003, truth, rng))
    elif kind == "dns_tunnel":
        for i in range(rng.randint(20, 40)):
            t += rng.uniform(0.4, 1.0)
            ev.append(_flow(t, src, victim, 53, "UDP", rng.randint(1, 2), rng.randint(1, 2),
                            rng.randint(180, 420), rng.randint(200, 650), rng.uniform(0.02, 0.2), truth, rng))
            if i == 9:
                ev.append(_alert(t + 0.001, src, victim, 53, "UDP", 1000004, truth, rng))
    else:
        raise ValueError(f"unknown attack kind: {kind}")
    return ev


def make_benign(kind: str, src: str, t0: float, rng: random.Random) -> list[dict]:
    victim = rng.choice(VICTIMS)
    ev: list[dict] = []
    t = t0

    def add(dport, proto, pts, ptc, bts, btc, age):
        ev.append(_flow(t, src, victim, dport, proto, pts, ptc, bts, btc, age, "benign", rng))

    if kind == "web_user":
        for _ in range(rng.randint(2, 12)):
            t += rng.uniform(0.5, 8.0)
            add(rng.choice([443, 443, 443, 80]), "TCP", rng.randint(8, 40), rng.randint(8, 60),
                rng.randint(500, 6000), rng.randint(3000, 200000), rng.uniform(0.3, 8))
    elif kind == "crawler":
        for _ in range(rng.randint(30, 70)):
            t += rng.uniform(0.1, 0.6)
            add(80, "TCP", rng.randint(6, 12), rng.randint(8, 30), rng.randint(400, 900),
                rng.randint(5000, 60000), rng.uniform(0.1, 0.8))
    elif kind == "admin_ssh":
        for _ in range(rng.randint(1, 3)):
            t += rng.uniform(1, 6)
            add(22, "TCP", rng.randint(200, 3000), rng.randint(200, 4000), rng.randint(15000, 400000),
                rng.randint(20000, 900000), rng.uniform(20, 400))
    elif kind == "monitor":
        for _ in range(rng.randint(5, 8)):
            t += rng.uniform(1, 3)
            add(rng.choice([22, 80, 443, 3306, 8080]), "TCP", rng.randint(3, 6), rng.randint(3, 6),
                rng.randint(200, 500), rng.randint(200, 900), rng.uniform(0.1, 0.5))
    elif kind == "dns_client":
        for _ in range(rng.randint(3, 15)):
            t += rng.uniform(0.5, 5.0)
            add(53, "UDP", 1, 1, rng.randint(60, 90), rng.randint(90, 200), rng.uniform(0.01, 0.1))
    elif kind == "misconfigured":
        for _ in range(rng.randint(6, 14)):
            t += rng.uniform(1, 4)
            replied = rng.random() > 0.4
            add(rng.choice([21, 23, 80, 443, 445, 3389, 8080]), "TCP", rng.randint(1, 4),
                rng.randint(1, 4) if replied else 0, rng.randint(60, 400),
                rng.randint(60, 600) if replied else 0, rng.uniform(0.05, 1.5))
    elif kind == "p2p":
        for _ in range(rng.randint(15, 50)):
            t += rng.uniform(0.02, 1.2)
            add(rng.randint(1024, 65000), "TCP", rng.randint(3, 40), rng.randint(3, 40),
                rng.randint(300, 20000), rng.randint(300, 20000), rng.uniform(0.2, 5))
    elif kind == "page_load":
        for _ in range(rng.randint(10, 40)):
            t += rng.uniform(0.01, 0.4)
            add(rng.choice([443, 443, 80]), "TCP", rng.randint(5, 30), rng.randint(5, 40),
                rng.randint(300, 2500), rng.randint(1500, 120000), rng.uniform(0.05, 2))
    elif kind == "internal_scanner":
        # an authorised vulnerability scan: same traffic as a hostile scan, so it also trips the rule
        for e in make_campaign("scan", src, t0, rng):
            e["netwatch"]["truth"] = "benign"
            ev.append(e)
    elif kind == "uptime_probe":
        for _ in range(rng.randint(6, 20)):
            t += rng.uniform(0.5, 3.0)
            ok = rng.random() > 0.25
            add(rng.choice([80, 443, 8080]), "TCP", rng.randint(1, 2), 1 if ok else 0,
                rng.randint(60, 120), rng.randint(60, 120) if ok else 0, rng.uniform(0.0, 0.3))
    elif kind == "iot_chatty":
        for _ in range(rng.randint(20, 60)):
            t += rng.uniform(0.2, 1.5)
            add(rng.choice([1883, 8883]), "TCP", rng.randint(2, 8), rng.randint(2, 8),
                rng.randint(80, 600), rng.randint(80, 600), rng.uniform(0.05, 1.0))
    else:
        raise ValueError(f"unknown benign kind: {kind}")
    return ev


def pick_kind(rng: random.Random, attack: bool) -> str:
    kinds, weights = (ATTACK_KINDS, ATTACK_WEIGHTS) if attack else (BENIGN_KINDS, BENIGN_WEIGHTS)
    return rng.choices(kinds, weights=weights, k=1)[0]


def build_history(now: float, hours: int, rng: random.Random) -> list[tuple[float, bool, str, str]]:
    """Plan (start_time, is_attack, kind, src_ip) tuples for the backfill, sorted by time."""
    pool = [random_attacker(rng) for _ in range(120)]
    peak = now - rng.uniform(5, 10) * 3600  # one busy period so the timeline has a shape
    plan: list[tuple[float, bool, str, str]] = []
    for h in range(hours):
        start = now - (hours - h) * 3600
        mid = start + 1800
        bump = math.exp(-((mid - peak) / 5400.0) ** 2)  # gaussian around the peak
        n_attacks = int(rng.uniform(10, 22) + 70 * bump)
        for _ in range(n_attacks):
            kind = pick_kind(rng, True)
            src = rng.choice(pool) if rng.random() < 0.55 else random_attacker(rng)
            plan.append((start + rng.uniform(0, 3500), True, kind, src))
        for _ in range(rng.randint(25, 45)):
            kind = pick_kind(rng, False)
            plan.append((start + rng.uniform(0, 3500), False, kind, random_benign(rng, kind)))
    plan.sort(key=lambda x: x[0])
    return plan


def make_episode(is_attack: bool, kind: str, src: str, t0: float, rng: random.Random) -> list[dict]:
    return make_campaign(kind, src, t0, rng) if is_attack else make_benign(kind, src, t0, rng)
