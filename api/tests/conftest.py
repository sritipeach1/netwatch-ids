import os
import random
import time

import pytest

from app.config import Settings
from app.db import Store
from app.ml import AnomalyModel
from app.pipeline import Bus, Pipeline
from app.response import ResponseEngine

MODEL = os.path.join(os.path.dirname(__file__), "..", "models", "flow_clf.joblib")


def make_settings(**kw) -> Settings:
    base = dict(mode="demo", db_path=":memory:", response_mode="simulated", allowlist=("127.0.0.0/8",),
                model_path=MODEL, backfill_hours=0, live_attacks=False, cors_origins=("http://localhost:3000",))
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def rng():
    return random.Random(1234)


@pytest.fixture
def parts():
    cfg = make_settings()
    store = Store(":memory:")
    resp = ResponseEngine(store, "simulated", ("127.0.0.0/8", "10.0.2.0/24"))
    model = AnomalyModel.load(MODEL, cfg.ml_threshold)
    pipe = Pipeline(store, resp, model, Bus(), cfg)
    return store, resp, pipe


def run_episode(pipe, events):
    for e in events:
        pipe.handle(e)
    pipe.flush(time.time() + 3600)
