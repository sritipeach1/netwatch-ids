import pytest

from app.db import Store
from app.response import FIRST_BLOCK_SECONDS, REPEAT_BLOCK_SECONDS, ResponseEngine


def engine(mode, calls=None, allow=("127.0.0.0/8",)):
    store = Store(":memory:")
    runner = (lambda cmd: calls.append(cmd)) if calls is not None else (lambda cmd: None)
    return store, ResponseEngine(store, mode, allow, runner=runner)


def test_off_mode_never_blocks():
    _, r = engine("off")
    assert r.block("203.0.113.5", "x", "port_scan", 100.0, 1, 1.0) is None


def test_dry_run_records_but_does_not_enforce():
    calls = []
    store, r = engine("dry-run", calls)
    b = r.block("203.0.113.5", "x", "port_scan", 100.0, 1, 1.0)
    assert b and b["mode"] == "dry-run" and calls == []
    assert not r.is_blocked("203.0.113.5", 101.0)  # dry-run does not drop traffic


def test_enforce_calls_nft_with_timeout():
    calls = []
    _, r = engine("enforce", calls)
    r.block("203.0.113.5", "x", "port_scan", 100.0, 1, 1.0)
    assert calls == [["nft", "add", "element", "inet", "netwatch", "blocklist", "{",
                      f"203.0.113.5 timeout {int(FIRST_BLOCK_SECONDS)}s", "}"]]
    assert r.is_blocked("203.0.113.5", 101.0)


def test_allowlist_and_garbage_are_never_blocked():
    calls = []
    _, r = engine("enforce", calls, allow=("10.0.2.0/24",))
    assert r.block("10.0.2.9", "x", "port_scan", 1.0, 1, 0.1) is None
    assert r.block("not-an-ip; rm -rf /", "x", "port_scan", 1.0, 1, 0.1) is None
    assert calls == []


def test_no_duplicate_active_block_and_expiry():
    store, r = engine("simulated")
    assert r.block("203.0.113.5", "x", "port_scan", 100.0, 1, 1.0)
    assert r.block("203.0.113.5", "again", "port_scan", 110.0, 2, 1.0) is None
    assert r.is_blocked("203.0.113.5", 200.0)
    assert not r.is_blocked("203.0.113.5", 100.0 + FIRST_BLOCK_SECONDS + 1)
    assert [b["ip"] for b in r.expire(100.0 + FIRST_BLOCK_SECONDS + 1)] == ["203.0.113.5"]


def test_repeat_offender_gets_longer_block():
    _, r = engine("simulated")
    first = r.block("203.0.113.5", "x", "port_scan", 0.0, 1, 1.0)
    r.expire(FIRST_BLOCK_SECONDS + 1)
    second = r.block("203.0.113.5", "x", "port_scan", FIRST_BLOCK_SECONDS + 10, 2, 1.0)
    assert first["expires"] - first["ts"] == FIRST_BLOCK_SECONDS
    assert second["expires"] - second["ts"] == REPEAT_BLOCK_SECONDS


def test_unblock_removes_nft_element():
    calls = []
    _, r = engine("enforce", calls)
    r.block("203.0.113.5", "x", "port_scan", 0.0, 1, 1.0)
    assert r.unblock("203.0.113.5") is True
    assert calls[-1][:3] == ["nft", "delete", "element"]
    assert r.unblock("203.0.113.5") is False


def test_bad_mode_rejected():
    with pytest.raises(ValueError):
        ResponseEngine(Store(":memory:"), "yolo")
