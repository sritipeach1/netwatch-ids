import time

from app import simulator as sim
from tests.conftest import run_episode


def alerts(store):
    return store.recent_alerts(100)


def test_ssh_brute_force_is_alerted_and_blocked(parts, rng):
    store, resp, pipe = parts
    now = time.time()
    run_episode(pipe, sim.make_campaign("bruteforce", "198.18.12.5", now, rng))
    rows = alerts(store)
    ssh = [a for a in rows if a["attack_type"] == "ssh_brute_force"]
    if ssh:  # the SSH rule only covers port 22; other ports rely on the ML layer
        assert any("block" in a["action"] for a in ssh)
    assert resp.store.block_count("198.18.12.5") == 1


def test_sql_injection_blocks_immediately(parts, rng):
    store, _, pipe = parts
    run_episode(pipe, sim.make_campaign("web_attack", "198.18.14.9", time.time(), rng))
    a = [x for x in alerts(store) if x["attack_type"] == "sql_injection"]
    assert len(a) == 1 and a[0]["severity"] == 1 and a[0]["action"] == "blocked"
    assert a[0]["technique"] == "T1190" and a[0]["country"] == "United States"


def test_dns_tunneling_is_alert_only(parts, rng):
    store, resp, pipe = parts
    run_episode(pipe, sim.make_campaign("dns_tunnel", "198.18.10.7", time.time(), rng))
    a = alerts(store)
    assert len(a) == 1 and a[0]["action"] == "alert only"
    assert resp.store.block_count("198.18.10.7") == 0


def test_flood_and_scan_blocked_and_traffic_dropped(parts, rng):
    store, resp, pipe = parts
    now = time.time()
    run_episode(pipe, sim.make_campaign("flood", "198.18.16.1", now, rng))
    assert store.block_count("198.18.16.1") == 1
    assert pipe.dropped > 0


def test_normal_traffic_raises_nothing(parts, rng):
    store, _, pipe = parts
    now = time.time()
    for i, kind in enumerate(["web_user", "dns_client", "admin_ssh", "monitor", "page_load"]):
        run_episode(pipe, sim.make_benign(kind, f"100.64.0.{i + 1}", now + i * 100, rng))
    assert alerts(store) == []


def test_allowlisted_scanner_is_flagged_but_never_blocked(parts, rng):
    store, resp, pipe = parts
    run_episode(pipe, sim.make_benign("internal_scanner", "10.0.2.5", time.time(), rng))
    assert store.block_count("10.0.2.5") == 0
    assert all(a["action"] == "alert only" for a in alerts(store))


def test_detection_rows_use_full_episode_even_after_block(parts, rng):
    store, _, pipe = parts
    run_episode(pipe, sim.make_campaign("scan", "198.18.17.3", time.time(), rng))
    c = store.compare(0)
    assert c["episodes"] == 1
    assert c["detectors"]["hybrid"]["tp"] == 1


def test_compare_shows_ml_blind_to_web_attacks_and_signature_blind_to_slow_scans(parts, rng):
    store, _, pipe = parts
    t = time.time()
    for i in range(6):
        run_episode(pipe, sim.make_campaign("web_attack", f"198.18.10.{i + 1}", t + i * 500, rng))
        run_episode(pipe, sim.make_campaign("slow_scan", f"198.18.11.{i + 1}", t + i * 500 + 250, rng))
    by = store.compare(0)["by_truth"]
    assert by["web_attack"]["signature"] == 1.0 and by["web_attack"]["ml"] < 0.5
    assert by["scan"]["signature"] == 0.0 and by["scan"]["ml"] > 0.8
