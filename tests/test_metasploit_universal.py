
from app.metasploit_universal import (
    MetasploitModule, TargetFingerprint, match_modules, build_validation_plan
)

def test_non_windows_target_can_match():
    fp = TargetFingerprint(
        target="10.10.10.20",
        platform="linux",
        architecture="x64",
        services=["http"],
        versions={"http": "example"},
        evidence=[{"type": "service_fingerprint"}],
    )
    module = MetasploitModule(
        name="exploit/example/linux_http",
        platforms=["linux"],
        services=["http"],
        architectures=["x64"],
        expected_outcomes=["session"],
        session_types=["meterpreter"],
    )
    matches = match_modules(fp, [module])
    assert len(matches) == 1
    assert matches[0]["expected_outcomes"] == ["session"]

def test_platform_agnostic_metadata():
    fp = TargetFingerprint(target="device-1", platform="embedded", services=["http"])
    module = MetasploitModule(
        name="exploit/example/embedded_http",
        platforms=["embedded"],
        services=["http"],
        expected_outcomes=["session"],
        session_types=["shell"],
    )
    m = match_modules(fp, [module])[0]
    plan = build_validation_plan(fp, m)
    assert plan["phase"] == "CHECK"
    assert plan["requires_scope_and_approval"] is True

def test_module_match_is_not_confirmation():
    fp = TargetFingerprint(target="host", platform="linux", services=["ssh"])
    module = MetasploitModule(
        name="exploit/example/ssh",
        platforms=["linux"],
        services=["ssh"],
    )
    m = match_modules(fp, [module])[0]
    assert m["evidence_required"] is True
    assert m["requires_scope_and_approval"] is True
