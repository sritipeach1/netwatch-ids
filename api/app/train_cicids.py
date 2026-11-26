"""
Train and evaluate the flow classifier on CIC-IDS2017 (real captured traffic).

    pip install -r requirements-train.txt
    python -m app.train_cicids --data path/to/TrafficLabelling

Writes:
    models/cicids2017.json        results the dashboard shows (small, commit it)
    models/cicids2017.joblib      the trained model (large, git-ignored)
    ../docs/cicids2017-results.md readable report for the repo

Evaluation is k-fold cross-validation grouped by 10-minute time blocks, so windows from the
same stretch of an attack never sit on both sides of a split. Every number in the report comes
from out-of-fold predictions. The live demo keeps its simulator model, which is what scores the
demo's simulated traffic.
"""
from __future__ import annotations

import argparse
import json
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold

from . import cicids
from .ml import FEATURES, AnomalyModel

CLASS_NAMES = {"benign": "Benign", "scan": "Port scan", "bruteforce": "Brute force", "flood": "DoS / flood"}


def make_model(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=100, max_depth=14, min_samples_leaf=3,
                                  class_weight="balanced_subsample", random_state=seed, n_jobs=-1)


def detection(y: np.ndarray, attack_score: np.ndarray, threshold: float) -> dict:
    """Attack-vs-benign view: does the window get flagged at all?"""
    is_attack = y != "benign"
    flagged = attack_score >= threshold
    tp = int((flagged & is_attack).sum()); fp = int((flagged & ~is_attack).sum())
    fn = int((~flagged & is_attack).sum()); tn = int((~flagged & ~is_attack).sum())
    return {
        "threshold": threshold,
        "recall": round(tp / max(tp + fn, 1), 4),
        "precision": round(tp / max(tp + fp, 1), 4),
        "false_alarm_rate": round(fp / max(fp + tn, 1), 5),
        "false_alarms": fp, "benign_windows": fp + tn, "attack_windows": tp + fn,
    }


def per_class(y: np.ndarray, pred: np.ndarray, classes: list[str]) -> dict:
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=classes, zero_division=0)
    return {c: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                "f1": round(float(f[i]), 4), "support": int(s[i])} for i, c in enumerate(classes)}


def label_with_threshold(probs: np.ndarray, classes: list[str], threshold: float) -> np.ndarray:
    """Same decision rule as AnomalyModel.predict: benign unless 1 - P(benign) >= threshold."""
    b = classes.index("benign")
    score = 1.0 - probs[:, b]
    masked = probs.copy(); masked[:, b] = -1
    best = np.array(classes)[masked.argmax(axis=1)]
    return np.where(score >= threshold, best, "benign"), score


def by_attack(windows: pd.DataFrame, flagged: np.ndarray, pred: np.ndarray) -> list[dict]:
    rows = []
    attacks = windows[windows["label"] != "benign"]
    for name, grp in attacks.groupby("attack"):
        idx = grp.index.to_numpy()
        rows.append({"attack": name, "class": grp["label"].iloc[0], "windows": int(len(idx)),
                     "detected": round(float(flagged[idx].mean()), 4),
                     "correct_type": round(float((pred[idx] == grp["label"].to_numpy()).mean()), 4)})
    return sorted(rows, key=lambda r: -r["windows"])


def write_report(res: dict, path: str) -> None:
    pct = lambda v: f"{v * 100:.1f}%"
    cv, d = res["cross_validation"], res["cross_validation"]["detection"]
    lines = [
        "# NetWatch on CIC-IDS2017",
        "",
        f"Flow classifier trained and evaluated on real captured traffic from CIC-IDS2017 "
        f"({res['data']['flows']:,} flows, {res['data']['windows']:,} per-source 60-second windows).",
        "",
        "## Method",
        "",
        f"- Features: NetWatch's 11 behaviour features per source over 60-second windows, "
        f"windows with at least {res['method']['min_flows']} flows.",
        f"- Classes: benign, port scan, brute force (FTP/SSH-Patator), DoS/flood (DoS Hulk, GoldenEye, "
        f"slowloris, Slowhttptest, DDoS). Web attacks, bots, infiltration and Heartbleed are left out "
        f"({res['data']['excluded_other']:,} windows): they are signature-rule territory.",
        f"- Evaluation: {res['method']['folds']}-fold cross-validation grouped by 10-minute time blocks. "
        f"Every figure below comes from out-of-fold predictions.",
        f"- Decision rule: as deployed, a window is flagged when 1 - P(benign) >= {d['threshold']}.",
        "",
        "## Results",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Macro F1 (4 classes) | {cv['macro_f1']['mean']:.3f} ± {cv['macro_f1']['std']:.3f} |",
        f"| Attack detection recall | {pct(d['recall'])} |",
        f"| Detection precision | {pct(d['precision'])} |",
        f"| False alarm rate (benign windows flagged) | {d['false_alarm_rate'] * 100:.2f}% "
        f"({d['false_alarms']:,} of {d['benign_windows']:,}) |",
        "",
        "### Per class",
        "",
        "| Class | Precision | Recall | F1 | Windows |",
        "| --- | --- | --- | --- | --- |",
    ]
    for c, m in cv["per_class"].items():
        lines.append(f"| {CLASS_NAMES.get(c, c)} | {pct(m['precision'])} | {pct(m['recall'])} | "
                     f"{m['f1']:.3f} | {m['support']:,} |")
    lines += ["", "### Per attack", "", "| Attack | Windows | Detected | Correct type |", "| --- | --- | --- | --- |"]
    for r in cv["by_attack"]:
        lines.append(f"| {r['attack']} | {r['windows']:,} | {pct(r['detected'])} | {pct(r['correct_type'])} |")
    t = res.get("simulator_model_on_real_data")
    if t:
        lines += ["", "## Does the simulator-trained model transfer?", "",
                  "The model the demo uses was trained only on simulated traffic. Scored on the same real windows:", "",
                  "| | Simulator model | Retrained on CIC-IDS2017 |", "| --- | --- | --- |",
                  f"| Attack detection recall | {pct(t['detection']['recall'])} | {pct(d['recall'])} |",
                  f"| False alarm rate | {t['detection']['false_alarm_rate'] * 100:.2f}% | {d['false_alarm_rate'] * 100:.2f}% |"]
    lines += ["", "## Caveats", "",
              "- CIC-IDS2017 is a lab capture from 2017 with known labelling errors (Engelen et al., 2021). "
              "Results are a benchmark, not a promise for any particular network.",
              "- Each attack type ran on a single day from a small set of machines, so time-block "
              "cross-validation tests unseen stretches of each attack, not unseen attackers.",
              "- CICFlowMeter byte counts are payload bytes; Suricata counts whole packets. The live sensor "
              "needs this model retrained on its own flow records before it is used there.",
              "- Most original files carry minute-level timestamps. For those, flow rate is counted over the "
              "full 60-second window.",
              "", f"Generated {time.strftime('%Y-%m-%d', time.gmtime(res['trained_at']))} by `python -m app.train_cicids`."]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="Folder with the CIC-IDS2017 labelled flow CSVs, or one CSV")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--min-flows", type=int, default=3)
    ap.add_argument("--max-benign", type=int, default=0,
                    help="Randomly keep at most this many benign windows (0 = keep all). Speeds up training.")
    ap.add_argument("--attempted", choices=["attack", "benign", "drop"], default="attack",
                    help="How to treat flows labelled '... - Attempted' in re-labelled versions")
    ap.add_argument("--threshold", type=float, default=0.80, help="Same as NETWATCH_ML_THRESHOLD")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--models", default="models")
    ap.add_argument("--report", default=os.path.join("..", "docs", "cicids2017-results.md"))
    args = ap.parse_args()
    t_start = time.time()

    print("Reading CSVs...")
    flows, files = cicids.load_dataset(args.data, args.attempted)
    print(f"{len(flows):,} flows. Building 60-second windows...")
    all_windows = cicids.build_windows(flows, args.min_flows)
    excluded = int((all_windows["label"] == cicids.OTHER).sum())
    windows = all_windows[all_windows["label"] != cicids.OTHER]
    if args.max_benign and (windows["label"] == "benign").sum() > args.max_benign:
        benign = windows[windows["label"] == "benign"].sample(args.max_benign, random_state=args.seed)
        windows = pd.concat([benign, windows[windows["label"] != "benign"]])
    windows = windows.reset_index(drop=True)
    info = cicids.describe(windows)
    print(f"{info['windows']:,} windows: " + ", ".join(f"{k} {v:,}" for k, v in info["by_class"].items()))
    missing = [c for c in cicids.CLASSES if c not in info["by_class"]]
    if missing:
        print(f"Note: no windows for {missing}. Include the CSV files for every day to cover all classes.")

    X = windows[FEATURES].to_numpy(dtype="float64")
    y = windows["label"].to_numpy()
    groups = windows["block"].to_numpy()
    classes = sorted(set(y))

    print(f"Cross-validating ({args.folds} folds grouped by 10-minute blocks)...")
    oof = np.zeros((len(y), len(classes)))
    fold_f1 = []
    cv = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=args.seed)
    for k, (tr, te) in enumerate(cv.split(X, y, groups), 1):
        clf = make_model(args.seed)
        clf.fit(X[tr], y[tr])
        probs = np.zeros((len(te), len(classes)))
        probs[:, [classes.index(c) for c in clf.classes_]] = clf.predict_proba(X[te])
        oof[te] = probs
        f1 = f1_score(y[te], np.array(classes)[probs.argmax(axis=1)], labels=classes, average="macro", zero_division=0)
        fold_f1.append(f1)
        print(f"  fold {k}: macro F1 {f1:.3f}")

    pred, score = label_with_threshold(oof, classes, args.threshold)
    flagged = score >= args.threshold
    result = {
        "trained_at": int(time.time()),
        "dataset": "CIC-IDS2017",
        "files": [{"name": os.path.basename(s.path), "flows": s.kept, "minute_timestamps": s.minute_resolution}
                  for s in files],
        "data": {"flows": int(len(flows)), "windows": info["windows"], "by_class": info["by_class"],
                 "excluded_other": excluded},
        "method": {"window_s": 60, "min_flows": args.min_flows, "folds": args.folds,
                   "grouping": "10-minute time blocks", "max_benign": args.max_benign or None,
                   "model": "Random forest, 100 trees, depth 14, balanced class weights"},
        "cross_validation": {
            "macro_f1": {"mean": round(float(np.mean(fold_f1)), 4), "std": round(float(np.std(fold_f1)), 4)},
            "per_class": per_class(y, pred, classes),
            "detection": detection(y, score, args.threshold),
            "detection_at_0_5": detection(y, score, 0.5),
            "confusion": {"labels": classes, "matrix": confusion_matrix(y, pred, labels=classes).tolist()},
            "by_attack": by_attack(windows, flagged, pred),
        },
    }

    sim_path = os.path.join(args.models, "flow_clf.joblib")
    sim = AnomalyModel.load(sim_path, args.threshold)
    if sim is not None:
        sp = sim.clf.predict_proba(X)
        s_pred, s_score = label_with_threshold(sp, list(sim.classes), args.threshold)
        result["simulator_model_on_real_data"] = {
            "detection": detection(y, s_score, args.threshold),
            "per_class": per_class(y, s_pred, classes),
        }

    print("Training the final model on all windows...")
    final = make_model(args.seed).fit(X, y)
    result["feature_importance"] = {f: round(float(i), 4) for f, i in
                                    sorted(zip(FEATURES, final.feature_importances_), key=lambda x: -x[1])}
    os.makedirs(args.models, exist_ok=True)
    joblib.dump({"clf": final, "classes": list(final.classes_)}, os.path.join(args.models, "cicids2017.joblib"),
                compress=3)
    json.dump(result, open(os.path.join(args.models, "cicids2017.json"), "w"), indent=2)
    write_report(result, args.report)

    d = result["cross_validation"]["detection"]
    print("\nDone in %.0f s." % (time.time() - t_start))
    print(f"Macro F1 {result['cross_validation']['macro_f1']['mean']:.3f} ± {result['cross_validation']['macro_f1']['std']:.3f}"
          f" | detection recall {d['recall']:.1%} | false alarm rate {d['false_alarm_rate']:.2%}")
    if "simulator_model_on_real_data" in result:
        t = result["simulator_model_on_real_data"]["detection"]
        print(f"Simulator-trained model on the same windows: recall {t['recall']:.1%}, false alarms {t['false_alarm_rate']:.2%}")
    print(f"Saved {os.path.join(args.models, 'cicids2017.json')} and the report at {args.report}")


if __name__ == "__main__":
    main()
