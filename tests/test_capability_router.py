
from app.capability_router import SecurityObjective, recommend_capabilities

def test_web_objective_is_not_tool_specific():
    r = recommend_capabilities(SecurityObjective(
        objective="Assess web API authorization and privilege paths",
        evidence=[{"service": "HTTP API"}],
    ))
    names = [x["name"] for x in r]
    assert "Web & API Security" in names
    assert "Attack Path & Graph" in names
    assert "Evidence & Findings" in names

def test_identity_environment_selects_identity_capability():
    r = recommend_capabilities(SecurityObjective(
        objective="Assess domain identity and Kerberos relationships",
    ))
    assert "Identity & Directory" in [x["name"] for x in r]

def test_exploitation_is_optional_and_objective_driven():
    r = recommend_capabilities(SecurityObjective(
        objective="Discover assets and map environment",
    ))
    names = [x["name"] for x in r]
    assert "Exploitation & Payloads" not in names
