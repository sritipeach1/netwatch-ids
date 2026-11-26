import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import make_settings


@pytest.fixture
def client():
    with TestClient(create_app(make_settings())) as c:
        yield c


def test_health(client):
    j = client.get("/api/health").json()
    assert j["status"] == "ok" and j["mode"] == "demo" and j["model_loaded"] is True


def test_empty_endpoints_are_well_formed(client):
    s = client.get("/api/stats").json()
    assert s["alerts"] == 0 and s["median_time_to_block"] is None
    assert len(client.get("/api/timeline?hours=6").json()) >= 6
    assert client.get("/api/alerts").json() == []
    assert client.get("/api/blocks").json() == []
    assert client.get("/api/compare").json()["episodes"] == 0


def test_bad_params_rejected(client):
    assert client.get("/api/stats?hours=0").status_code == 422
    assert client.get("/api/alerts?action=drop-table").status_code == 422


def test_simulate_validates_and_rate_limits(client):
    assert client.post("/api/simulate", json={"attack": "nope"}).status_code == 422
    ok = client.post("/api/simulate", json={"attack": "web_attack"})
    assert ok.status_code == 200 and ok.json()["src_ip"].startswith("198.18.")
    assert client.post("/api/simulate", json={"attack": "web_attack"}).status_code == 429


def test_simulated_attack_shows_up_and_can_be_unblocked(client):
    ip = client.post("/api/simulate", json={"attack": "web_attack"}).json()["src_ip"]
    deadline = time.time() + 8
    while time.time() < deadline and not client.get("/api/blocks").json():
        time.sleep(0.2)
    blocks = client.get("/api/blocks").json()
    assert [b["ip"] for b in blocks] == [ip]
    assert client.get("/api/alerts?action=blocked").json()[0]["src_ip"] == ip
    assert client.post(f"/api/blocks/{ip}/unblock").status_code == 200
    assert client.post(f"/api/blocks/{ip}/unblock").status_code == 404


def test_live_mode_requires_api_key_and_has_no_simulation(monkeypatch):
    monkeypatch.setenv("NETWATCH_API_KEY", "secret")
    cfg = make_settings(mode="live", response_mode="dry-run", eve_path="/nonexistent/eve.json")
    with TestClient(create_app(cfg)) as c:
        assert c.post("/api/blocks/203.0.113.9/unblock").status_code == 403
        assert c.post("/api/blocks/203.0.113.9/unblock", headers={"X-API-Key": "secret"}).status_code == 404
        assert c.post("/api/simulate", json={"attack": "scan"}).status_code == 404


def test_real_eval_is_404_until_generated(client, tmp_path):
    assert client.get("/api/model/real-eval").status_code == 404
    import shutil
    from tests.conftest import MODEL
    shutil.copy(MODEL, tmp_path / "flow_clf.joblib")
    (tmp_path / "cicids2017.json").write_text('{"dataset": "CIC-IDS2017"}')
    with TestClient(create_app(make_settings(model_path=str(tmp_path / "flow_clf.joblib")))) as c:
        assert c.get("/api/model/real-eval").json()["dataset"] == "CIC-IDS2017"
