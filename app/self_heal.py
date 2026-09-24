
"""ASEP self-healing orchestration with deterministic recovery and controlled patching."""
import shutil
import time
from pathlib import Path


KNOWN_TOOLS = ("nmap", "msfconsole")


def diagnose(cfg):
    checks = []
    for binary in KNOWN_TOOLS:
        checks.append({"binary": binary, "installed": bool(shutil.which(binary))})
    checks.append({"config_root_exists": Path(cfg["root"]).exists()})
    return {
        "ok": all(x.get("installed", True) for x in checks if "installed" in x),
        "checks": checks,
    }


def retry_once(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), {"attempts": 1, "recovered": False}
    except Exception as first:
        time.sleep(0.25)
        try:
            return fn(*args, **kwargs), {"attempts": 2, "recovered": True, "first_error": str(first)}
        except Exception as second:
            raise second


def health(cfg):
    return diagnose(cfg)


def repair_with_patch(cfg, changes, approved=False, run_tests=True):
    """Checkpoint → patch → validate → rollback on failure."""
    if not cfg.get("self_modify_enabled", False):
        return {"ok": False, "status": "DISABLED", "error": "Self-modifying is disabled."}
    if cfg.get("self_modify_approval_required", True) and not approved:
        return {"ok": False, "status": "APPROVAL_REQUIRED", "error": "Explicit approval required."}

    from .self_modifying import SelfModifier
    modifier = SelfModifier(cfg["root"], cfg.get("self_modify_max_file_bytes", 500000))
    return modifier.apply_and_validate(changes, run_tests=run_tests)
