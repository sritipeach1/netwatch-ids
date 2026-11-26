"""
Turn CIC-IDS2017 flow CSVs into NetWatch's per-source window features.

Works with the labelled flow CSVs that keep source IPs and timestamps: the official
GeneratedLabelledFlows ("TrafficLabelling") files, and re-labelled versions that use similar
CICFlowMeter column names. The MachineLearningCSV files will not work: they drop IPs and times,
so there is no way to group flows by source.

Each flow is mapped to the same row the live pipeline builds from a Suricata flow event:
    (ts, dest_port, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, duration_s)
Flows are then grouped per source into 60-second windows, and the 11 features are computed
with the same formulas as ml.window_features.
"""
from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .ml import FEATURES, WINDOW_SECONDS

# Canonical column -> accepted spellings, compared after lowercasing and dropping non-alphanumerics.
ALIASES: dict[str, tuple[str, ...]] = {
    "src": ("sourceip", "srcip", "srcaddr", "sourceaddress"),
    "dport": ("destinationport", "dstport", "destport", "dport"),
    "ts": ("timestamp", "time", "starttime"),
    "duration": ("flowduration",),
    "pkts_ts": ("totalfwdpackets", "totalfwdpacket", "totfwdpkts", "fwdpkts", "totalforwardpackets"),
    "pkts_tc": ("totalbackwardpackets", "totalbwdpackets", "totalbwdpacket", "totbwdpkts", "bwdpkts"),
    "bytes_ts": ("totallengthoffwdpackets", "totallengthoffwdpacket", "totlenfwdpkts", "fwdbytes",
                 "totalfwdbytes"),
    "bytes_tc": ("totallengthofbwdpackets", "totallengthofbwdpacket", "totlenbwdpkts", "bwdbytes",
                 "totalbwdbytes"),
    "label": ("label",),
}
NUMERIC = ("dport", "duration", "pkts_ts", "pkts_tc", "bytes_ts", "bytes_tc")
CLASSES = ["benign", "scan", "bruteforce", "flood"]  # NetWatch's classifier classes
OTHER = "other"  # attacks the flow classifier is not meant to catch (web attacks, bots, ...)


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


_LOOKUP = {alias: canon for canon, aliases in ALIASES.items() for alias in aliases}


# ---------------------------------------------------------------- labels

def clean_label(raw: str) -> str:
    """'Web Attack � Brute Force' -> 'Web Attack - Brute Force'; trims spaces."""
    s = str(raw).encode("ascii", "replace").decode("ascii").replace("?", "-")
    return re.sub(r"\s+", " ", s).strip()


def map_label(raw: str, attempted: str = "attack") -> tuple[str, str]:
    """Return (netwatch_class, attack_name). attempted: attack | benign | drop."""
    name = clean_label(raw)
    low = name.lower()
    if "attempted" in low:
        base = re.sub(r"\s*-?\s*attempted\s*$", "", name, flags=re.I).strip()
        if attempted == "benign":
            return "benign", "BENIGN"
        if attempted == "drop":
            return "drop", base
        name, low = base, base.lower()
    if low in ("benign", "normal", ""):
        return "benign", "BENIGN"
    if low.startswith("web") or "xss" in low or "sql" in low:
        return OTHER, name
    if "portscan" in low.replace(" ", ""):
        return "scan", name
    if "patator" in low or "brute" in low:
        return "bruteforce", name
    if low.startswith("ddos") or low.startswith("dos"):
        return "flood", name
    return OTHER, name  # bot, infiltration, heartbleed, ...


# ---------------------------------------------------------------- timestamps

_FORMATS = [
    ("%d/%m/%Y %H:%M:%S", True), ("%d/%m/%Y %H:%M", True),
    ("%d/%m/%Y %I:%M:%S %p", False), ("%d/%m/%Y %I:%M %p", False),
    ("%Y-%m-%d %H:%M:%S.%f", False), ("%Y-%m-%d %H:%M:%S", False), ("%Y-%m-%d %H:%M", False),
]


def parse_timestamps(values: pd.Series) -> tuple[np.ndarray, bool]:
    """Return (epoch seconds as float, minute_resolution).

    The original CIC CSVs write day-first dates and, in most files, a 12-hour clock without
    AM/PM ("7/7/2017 3:30" means 15:30). Capture ran 9:00 to 17:00, so hours below 8 are
    afternoon and get 12 hours added.
    """
    s = values.astype(str).str.strip()
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.99:
        x = num.to_numpy(dtype="float64")
        med = np.nanmedian(x)
        x = x / (1e6 if med > 1e14 else 1e3 if med > 1e11 else 1.0)
        return x, False

    sample = s.dropna().head(2000)
    best, best_ok = None, 0.0
    for fmt, ampm_less in _FORMATS:
        ok = pd.to_datetime(sample, format=fmt, errors="coerce").notna().mean()
        if ok > best_ok:
            best, best_ok = (fmt, ampm_less), ok
        if ok > 0.99:
            break
    if best is None or best_ok < 0.9:
        raise ValueError(f"Couldn't read the Timestamp column. Example values: {list(sample.head(3))}")
    fmt, ampm_less = best
    dt = pd.to_datetime(s, format=fmt, errors="coerce")
    if ampm_less and fmt.startswith("%d/%m/%Y"):
        dt = dt.where(dt.dt.hour >= 8, dt + pd.Timedelta(hours=12))
    minute_res = bool((dt.dropna().dt.second == 0).mean() > 0.99)
    epoch = (dt - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)
    return epoch.to_numpy(dtype="float64"), minute_res


# ---------------------------------------------------------------- loading

@dataclass
class FileSummary:
    path: str
    rows: int
    kept: int
    minute_resolution: bool
    labels: dict = field(default_factory=dict)


def find_csvs(data: str) -> list[str]:
    if os.path.isfile(data):
        return [data]
    files = sorted(glob.glob(os.path.join(data, "**", "*.csv"), recursive=True))
    if not files:
        raise FileNotFoundError(f"No .csv files found under {data}")
    return files


def load_csv(path: str, attempted: str = "attack") -> tuple[pd.DataFrame, FileSummary]:
    header = pd.read_csv(path, nrows=0, encoding="latin-1")
    rename = {c: _LOOKUP[_norm(c)] for c in header.columns if _norm(c) in _LOOKUP}
    missing = [k for k in ALIASES if k not in rename.values()]
    if missing:
        raise ValueError(
            f"{os.path.basename(path)} is missing {missing}. This needs the labelled flow CSVs with "
            f"source IPs and timestamps (GeneratedLabelledFlows / TrafficLabelling), not MachineLearningCSV. "
            f"Columns found: {list(header.columns)[:12]}...")
    # keep only the first column for each canonical name
    keep, seen = {}, set()
    for c, canon in rename.items():
        if canon not in seen:
            keep[c], seen = canon, seen | {canon}
    df = pd.read_csv(path, usecols=list(keep), encoding="latin-1", low_memory=False).rename(columns=keep)
    rows = len(df)
    df = df.dropna(subset=["src", "ts", "label"])
    for c in NUMERIC:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=list(NUMERIC))
    df["ts"], minute_res = parse_timestamps(df["ts"])
    df = df.dropna(subset=["ts"])

    mapped = df["label"].map(lambda v: map_label(v, attempted))
    df["cls"] = mapped.map(lambda t: t[0])
    df["attack"] = mapped.map(lambda t: t[1])
    df = df[df["cls"] != "drop"]
    df["src"] = df["src"].astype(str).str.strip()
    df["duration"] = df["duration"].clip(lower=0) / 1e6  # CICFlowMeter durations are microseconds
    for c in ("pkts_ts", "pkts_tc", "bytes_ts", "bytes_tc"):
        df[c] = df[c].clip(lower=0)
    df["minute_res"] = minute_res
    summary = FileSummary(path, rows, len(df), minute_res, df["attack"].value_counts().to_dict())
    cols = ["src", "ts", "dport", "pkts_ts", "pkts_tc", "bytes_ts", "bytes_tc", "duration",
            "cls", "attack", "minute_res"]
    return df[cols].reset_index(drop=True), summary


def load_dataset(data: str, attempted: str = "attack", log=print) -> tuple[pd.DataFrame, list[FileSummary]]:
    frames, summaries = [], []
    for path in find_csvs(data):
        df, s = load_csv(path, attempted)
        log(f"  {os.path.basename(path)}: {s.kept:,} flows"
            f"{', minute timestamps' if s.minute_resolution else ''}")
        frames.append(df)
        summaries.append(s)
    return pd.concat(frames, ignore_index=True), summaries


# ---------------------------------------------------------------- windows

def build_windows(flows: pd.DataFrame, min_flows: int = 3, window: float = WINDOW_SECONDS) -> pd.DataFrame:
    """One row per (source, 60-second window) with the 11 features, a label, and a time block.

    Windows are tumbling (fixed 60-second buckets). The live pipeline re-scores a rolling
    60-second window every few flows; tumbling buckets compute the same features without
    near-duplicate rows. Label rule matches Episode.truth: any attack flow beats benign noise,
    and the most frequent attack class wins.
    """
    f = flows.copy()
    f["win"] = np.floor(f["ts"] / window).astype("int64")
    f["no_reply"] = (f["pkts_tc"] == 0).astype("float64")
    f["ssh"] = (f["dport"] == 22).astype("float64")
    keys = ["src", "win"]
    g = f.groupby(keys, sort=False)
    out = g.agg(
        n=("ts", "size"), t0=("ts", "min"), t1=("ts", "max"), uniq=("dport", "nunique"),
        no_reply=("no_reply", "mean"), bytes_ts=("bytes_ts", "mean"), bytes_tc=("bytes_tc", "mean"),
        pkts_ts=("pkts_ts", "mean"), duration=("duration", "mean"), ssh=("ssh", "mean"),
        minute_res=("minute_res", "max"),
    )
    top = f.groupby(keys + ["dport"], sort=False).size().groupby(level=[0, 1]).max()
    out["top"] = top.reindex(out.index).to_numpy()

    votes = f.groupby(keys + ["cls"], sort=False).size().unstack(fill_value=0)
    attack_cols = [c for c in votes.columns if c != "benign"]
    if attack_cols:
        av = votes[attack_cols]
        has_attack = av.sum(axis=1) > 0
        label = pd.Series("benign", index=votes.index)
        label[has_attack] = av[has_attack].idxmax(axis=1)
    else:
        label = pd.Series("benign", index=votes.index)
    out["label"] = label.reindex(out.index).to_numpy()

    names = (f[f["cls"] != "benign"].groupby(keys + ["cls"], sort=False)["attack"]
             .agg(lambda a: a.value_counts().index[0]))
    out["attack"] = "BENIGN"
    lab_idx = pd.MultiIndex.from_arrays([out.index.get_level_values(0), out.index.get_level_values(1),
                                         out["label"].to_numpy()])
    found = names.reindex(lab_idx)
    out.loc[found.notna().to_numpy(), "attack"] = found.dropna().to_numpy()

    out = out[out["n"] >= min_flows].copy()
    span = np.where(out["minute_res"], window, np.maximum(out["t1"] - out["t0"], 1.0))
    n = out["n"].to_numpy(dtype="float64")
    feats = pd.DataFrame({
        "log_flows": np.log1p(n),
        "log_flows_per_s": np.log1p(n / span),
        "log_unique_ports": np.log1p(out["uniq"].to_numpy(dtype="float64")),
        "unique_port_ratio": out["uniq"].to_numpy(dtype="float64") / n,
        "no_reply_ratio": out["no_reply"].to_numpy(),
        "log_mean_bytes_out": np.log1p(out["bytes_ts"].to_numpy()),
        "log_mean_bytes_in": np.log1p(out["bytes_tc"].to_numpy()),
        "log_mean_pkts_out": np.log1p(out["pkts_ts"].to_numpy()),
        "log_mean_duration": np.log1p(out["duration"].to_numpy()),
        "top_port_share": out["top"].to_numpy(dtype="float64") / n,
        "ssh_share": out["ssh"].to_numpy(),
    }, index=out.index)
    assert list(feats.columns) == FEATURES
    feats["label"] = out["label"]
    feats["attack"] = out["attack"]
    feats["flows"] = out["n"]
    # 10-minute time blocks: neighbouring windows stay on the same side of a train/test split
    feats["block"] = (np.floor(out["t0"] / 600.0)).astype("int64").to_numpy()
    return feats.reset_index()


def describe(windows: pd.DataFrame) -> dict:
    return {
        "windows": int(len(windows)),
        "by_class": {k: int(v) for k, v in windows["label"].value_counts().items()},
        "by_attack": {k: int(v) for k, v in windows["attack"].value_counts().items()},
    }

