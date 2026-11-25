"""
Train the flow classifier.   python -m app.training [--episodes 2500] [--seed 7]

The training data comes from the simulator. Window features are extracted with the same aggregator
and the same evaluation cadence the live pipeline uses, so train and serve see identical features.
Web attacks and DNS tunneling are deliberately left out: they look like normal flows at this level,
which is exactly the gap the signature rules cover.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import GroupShuffleSplit

from .eve import parse_event, Flow
from .ml import FEATURES, LABELS, FlowAggregator
from . import simulator as sim

LABEL_OF = {"scan": "scan", "slow_scan": "scan", "bruteforce": "bruteforce", "flood": "flood"}


def collect(n_episodes: int, seed: int):
    rng = random.Random(seed)
    X, y, groups = [], [], []
    t0 = 1_700_000_000.0
    for gid in range(n_episodes):
        is_attack = rng.random() < 0.55
        kind = sim.pick_kind(rng, is_attack)
        if is_attack and kind not in LABEL_OF:
            continue
        label = LABEL_OF[kind] if is_attack else "benign"
        src = sim.random_attacker(rng) if is_attack else sim.random_benign(rng, kind)
        agg = FlowAggregator()
        t0 += 600
        for raw in sim.make_episode(is_attack, kind, src, t0, rng):
            ev = parse_event(raw)
            if not isinstance(ev, Flow):
                continue
            ep, _ = agg.add_flow(ev)
            if agg.due(ep, ev.ts):
                X.append(agg.features(ep)); y.append(label); groups.append(gid)
                ep.new_since_eval = 0; ep.last_eval = ev.ts
    return np.array(X), np.array(y), np.array(groups)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=2500)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="models/flow_clf.joblib")
    args = ap.parse_args()

    X, y, groups = collect(args.episodes, args.seed)
    split = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=args.seed)
    tr, te = next(split.split(X, y, groups))
    clf = RandomForestClassifier(n_estimators=40, max_depth=10, min_samples_leaf=3,
                                 class_weight="balanced", random_state=args.seed, n_jobs=1)
    clf.fit(X[tr], y[tr])
    pred = clf.predict(X[te])
    report = classification_report(y[te], pred, output_dict=True, zero_division=0)

    # final model on all data
    clf.fit(X, y)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump({"clf": clf, "classes": list(clf.classes_)}, args.out)
    meta = {
        "trained_at": int(time.time()), "episodes": args.episodes, "windows": int(len(X)),
        "features": FEATURES, "classes": list(clf.classes_), "data": "simulated flows",
        "holdout": {k: {m: round(v, 3) for m, v in d.items()} for k, d in report.items()
                    if isinstance(d, dict)},
        "feature_importance": {f: round(float(i), 3) for f, i in
                               sorted(zip(FEATURES, clf.feature_importances_), key=lambda x: -x[1])},
    }
    json.dump(meta, open(os.path.splitext(args.out)[0] + ".json", "w"), indent=2)
    print(classification_report(y[te], pred, zero_division=0))
    print("saved", args.out, "windows:", len(X))


if __name__ == "__main__":
    main()
