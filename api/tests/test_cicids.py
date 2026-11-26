import math

import pandas as pd
import pytest

from app import cicids
from app.ml import FEATURES, window_features

HEADER = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,"
          " Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets,"
          " Total Length of Bwd Packets, Label\n")


def test_labels_map_to_netwatch_classes():
    assert cicids.map_label("BENIGN") == ("benign", "BENIGN")
    assert cicids.map_label("PortScan")[0] == "scan"
    assert cicids.map_label("SSH-Patator") == ("bruteforce", "SSH-Patator")
    assert cicids.map_label("DoS slowloris")[0] == "flood"
    assert cicids.map_label("DDoS")[0] == "flood"
    # web attacks are signature territory, even the "Brute Force" one
    assert cicids.map_label("Web Attack � Brute Force") == ("other", "Web Attack - Brute Force")
    assert cicids.map_label("Heartbleed")[0] == "other"
    assert cicids.map_label("Bot")[0] == "other"
    assert cicids.map_label("FTP-Patator - Attempted") == ("bruteforce", "FTP-Patator")
    assert cicids.map_label("FTP-Patator - Attempted", attempted="drop")[0] == "drop"


def test_day_first_timestamps_and_afternoon_fix():
    ts, minute = cicids.parse_timestamps(pd.Series(["4/7/2017 9:20", "4/7/2017 2:05", "4/7/2017 12:30"]))
    hours = pd.to_datetime(ts, unit="s").hour.tolist()
    assert hours == [9, 14, 12]  # "2:05" with no AM/PM is 14:05
    assert pd.to_datetime(ts[0], unit="s").month == 7  # day first: 4 July, not 7 April
    assert minute is True


def test_second_and_iso_timestamps():
    ts, minute = cicids.parse_timestamps(pd.Series(["03/07/2017 08:55:58", "03/07/2017 09:01:02"]))
    assert minute is False and ts[1] - ts[0] == pytest.approx(304)
    ts, _ = cicids.parse_timestamps(pd.Series(["2017-07-05 14:00:01.5", "2017-07-05 14:00:03.0"]))
    assert ts[1] - ts[0] == pytest.approx(1.5)


def test_window_features_match_the_live_pipeline():
    base = 1_499_000_040.0
    rows = [(base + i * 0.7, [22, 22, 80, 443][i % 4], 3 + i % 5, 0 if i % 3 == 0 else 4, 200 + i, 900 + 2 * i, 0.5 + i / 10)
            for i in range(30)]
    flows = pd.DataFrame(rows, columns=["ts", "dport", "pkts_ts", "pkts_tc", "bytes_ts", "bytes_tc", "duration"])
    flows["src"], flows["cls"], flows["attack"], flows["minute_res"] = "10.0.0.9", "benign", "BENIGN", False
    out = cicids.build_windows(flows)
    assert len(out) == 1
    expected = window_features(rows)
    for name, value in zip(FEATURES, expected):
        assert out.loc[0, name] == pytest.approx(value), name


def test_attack_flows_label_the_window():
    flows = pd.DataFrame({
        "src": ["172.16.0.1"] * 6, "ts": [60.0 * 100 + i for i in range(6)], "dport": [21] * 6,
        "pkts_ts": [5] * 6, "pkts_tc": [5] * 6, "bytes_ts": [100] * 6, "bytes_tc": [100] * 6, "duration": [1.0] * 6,
        "cls": ["benign"] * 4 + ["bruteforce"] * 2, "attack": ["BENIGN"] * 4 + ["FTP-Patator"] * 2,
        "minute_res": [False] * 6})
    out = cicids.build_windows(flows)
    assert out.loc[0, "label"] == "bruteforce" and out.loc[0, "attack"] == "FTP-Patator"


def test_minute_timestamps_use_the_full_window_for_rate():
    flows = pd.DataFrame({
        "src": ["a"] * 12, "ts": [6000.0] * 12, "dport": range(12), "pkts_ts": [1] * 12, "pkts_tc": [0] * 12,
        "bytes_ts": [0] * 12, "bytes_tc": [0] * 12, "duration": [0.0] * 12, "cls": ["scan"] * 12,
        "attack": ["PortScan"] * 12, "minute_res": [True] * 12})
    out = cicids.build_windows(flows)
    assert out.loc[0, "log_flows_per_s"] == pytest.approx(math.log1p(12 / 60))


def test_load_csv_handles_the_real_files_quirks(tmp_path):
    p = tmp_path / "Tuesday.csv"
    body = (HEADER +
            "f1,172.16.0.1,4000,192.168.10.50,22,6,4/7/2017 2:01,1500000,10,9,900,1800,SSH-Patator\n"
            "f2,192.168.10.3,4001,8.8.8.8,53,17,4/7/2017 2:01,2000,1,1,40,120,BENIGN\n"
            "f3,172.16.0.1,4002,192.168.10.50,80,6,4/7/2017 2:02,-1,2,0,0,0,Web Attack \x96 XSS\n"
            ",,,,,,,,,,,,\n")
    p.write_bytes(body.encode("latin-1"))
    df, summary = cicids.load_csv(str(p))
    assert summary.kept == 3 and summary.minute_resolution
    assert df.loc[0, "duration"] == pytest.approx(1.5)  # microseconds to seconds
    assert df.loc[2, "duration"] == 0  # negative durations in the CSVs are clipped
    assert df["cls"].tolist() == ["bruteforce", "benign", "other"]
    assert pd.to_datetime(df.loc[0, "ts"], unit="s").hour == 14


def test_machine_learning_csv_is_rejected_with_a_clear_message(tmp_path):
    p = tmp_path / "ml.csv"
    p.write_text(" Destination Port, Flow Duration, Label\n80,10,BENIGN\n")
    with pytest.raises(ValueError, match="TrafficLabelling"):
        cicids.load_csv(str(p))
