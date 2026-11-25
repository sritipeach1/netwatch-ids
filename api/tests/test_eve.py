from app.eve import AlertEvent, Flow, format_ts, parse_event, parse_ts


def test_roundtrip_timestamp():
    assert abs(parse_ts(format_ts(1_700_000_000.5)) - 1_700_000_000.5) < 1e-3


def test_parse_flow():
    ev = {"timestamp": format_ts(100.0), "event_type": "flow", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.1",
          "dest_port": 22, "proto": "tcp",
          "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 300, "bytes_toclient": 200, "age": 1.5}}
    f = parse_event(ev)
    assert isinstance(f, Flow) and f.dest_port == 22 and f.proto == "TCP" and f.duration == 1.5


def test_parse_alert():
    ev = {"timestamp": format_ts(100.0), "event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.1",
          "dest_port": 80, "proto": "TCP", "alert": {"signature_id": 1000003, "signature": "x", "severity": 1}}
    a = parse_event(ev)
    assert isinstance(a, AlertEvent) and a.sid == 1000003 and a.severity == 1


def test_ignores_other_and_malformed():
    assert parse_event({"event_type": "dns", "timestamp": format_ts(1), "src_ip": "1.1.1.1"}) is None
    assert parse_event({"event_type": "alert"}) is None
    assert parse_event({"event_type": "flow", "timestamp": format_ts(1)}) is None
