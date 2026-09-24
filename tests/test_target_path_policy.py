
from app.target_path import CandidateAsset, passive_deep_dive, build_paths

def test_out_of_scope_requires_confirmation():
    c = CandidateAsset(
        target="10.20.30.40",
        scope_status="OUT_OF_SCOPE",
        evidence=[{"type": "certificate"}],
        relationships=[{"weight": 0.2, "reason": "shares certificate relation"}],
    )
    r = passive_deep_dive(c)
    assert r["passive_only"] is True
    assert r["requires_confirmation"] is True
    assert r["active_testing_allowed"] is False

def test_in_scope_can_continue():
    c = CandidateAsset(target="192.168.1.10", scope_status="IN_SCOPE")
    r = passive_deep_dive(c)
    assert r["requires_confirmation"] is False
    assert r["active_testing_allowed"] is True

def test_path_graph():
    paths = build_paths("A", [
        {"from": "A", "to": "B"},
        {"from": "B", "to": "C"},
    ])
    assert ["A", "B"] in paths
    assert ["A", "B", "C"] in paths
