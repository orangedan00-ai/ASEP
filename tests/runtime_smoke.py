
"""Real Flask runtime smoke test.

This test intentionally requires the runtime dependency. validate_build.sh
runs it automatically when Flask is installed and reports a clear bootstrap
instruction otherwise.
"""
import importlib.util
import tempfile
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

if not importlib.util.find_spec("flask"):
    print("RUNTIME_SMOKE: SKIPPED - Flask is not installed in this environment.")
    print("Install with: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt")
    raise SystemExit(0)

from app.config import load_config
from app.version import VERSION
from app.db import init_db
from app.routes import create_app

with tempfile.TemporaryDirectory() as td:
    # Keep the real package root for VERSION/templates/static; isolate only the database.
    cfg = load_config()
    cfg["data_root"] = Path(td)
    cfg["scope"] = {"scope": {"networks": ["127.0.0.0/8"], "hosts": ["localhost"]}}
    cfg["local_enabled"] = False
    cfg["openai_api_key"] = ""
    cfg["self_modify_enabled"] = False
    init_db(cfg)
    app = create_app(cfg)
    app.testing = True

    client = app.test_client()
    for path in [
        "/api/status",
        "/api/monitor",
        "/api/skills",
        "/api/intelligence/status",
        "/api/evidence",
        "/api/v2/dashboard",
        "/api/v2/targets",
        "/api/v2/evidence",
        "/api/v2/findings",
        "/api/v2/attack-paths",
        "/api/v2/recommendations",
        "/api/v2/sessions",
        "/api/v2/activity",
        "/api/v2/capabilities",
        "/api/environment",
        "/api/network-discovery/status",
        "/api/network-discovery/history",
        "/api/v2/environment",
        "/api/v2/discovery-history",
    ]:
        response = client.get(path)
        assert response.status_code == 200, (path, response.status_code, response.data[:500])
    status = client.get("/api/status")
    assert status.get_json()["version"] == VERSION, status.get_json()

    payloads = [
        ("/api/capabilities/recommend", {"objective": "Assess web API authorization"}),
        ("/api/replan", {"objective": "validate boundary", "failed_actions": [{"action_id": "X"}]}),
        ("/api/target-path/passive-deep-dive", {
            "target": "candidate.example",
            "scope_status": "OUT_OF_SCOPE",
            "evidence": [{"type": "certificate"}],
        }),
        ("/api/post-session/advice", {
            "session_id": "1", "target": "127.0.0.1",
            "platform": "Linux", "privilege": "standard",
        }),
        ("/api/metasploit/universal/match", {
            "target": "127.0.0.1", "platform": "linux",
            "architecture": "x64", "services": ["http"],
            "modules": [{
                "name": "exploit/example/linux_http",
                "platforms": ["linux"], "services": ["http"],
                "architectures": ["x64"], "supports_check": True,
                "expected_outcomes": ["session"], "session_types": ["shell"],
                "prerequisites": []
            }]
        }),
    ]
    for path, payload in payloads:
        response = client.post(path, json=payload)
        assert response.status_code == 200, (path, response.status_code, response.data[:1000])

print("RUNTIME_SMOKE: PASS")
