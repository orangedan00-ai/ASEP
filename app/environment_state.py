"""Lifecycle state for network-dependent ASEP data.

ASEP is a portable network assessment appliance. Network identity can change
between laptop boots or when DHCP assigns a different address. This module
keeps network-derived inventory tied to the current environment so stale IP
addresses/services are not carried into a new connection.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import reset_network_state
from .network_discovery import local_context


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def current_environment_identity() -> dict[str, Any]:
    ctx = local_context()
    primary = next((c for c in ctx.get("candidates", []) if c.get("primary")), None)
    if primary is None:
        primary = next(
            (c for c in ctx.get("candidates", []) if c.get("kind") in {"ethernet", "wifi"}),
            None,
        )
    return {
        "boot_id": _boot_id(),
        "network": (primary or {}).get("network"),
        "interface": (primary or {}).get("interface"),
        "kind": (primary or {}).get("kind"),
        "local_ip": (primary or {}).get("local_ip"),
        "gateway": (primary or {}).get("gateway") or ctx.get("gateway"),
    }


def _state_path(cfg) -> Path:
    path = Path(cfg.get("data_root", cfg["root"])) / "data" / "environment_state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load_state(cfg) -> dict[str, Any] | None:
    try:
        return json.loads(_state_path(cfg).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def _has_network_state(cfg) -> bool:
    from .db import connect
    try:
        con = connect(cfg)
        targets = con.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        evidence = con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        runs = con.execute("SELECT COUNT(*) FROM discovery_runs").fetchone()[0]
        con.close()
        return bool(targets or evidence or runs)
    except Exception:
        return False


def _write_state(cfg, identity: dict[str, Any]) -> None:
    try:
        _state_path(cfg).write_text(json.dumps(identity, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def prepare_environment_state(cfg) -> dict[str, Any]:
    """Synchronize the current network identity and clean stale network data.

    A cleanup occurs when the OS boot changes, when the active network identity
    changes (network/interface/local IP/gateway), or when an existing database
    has network-derived state but no lifecycle marker yet.
    """
    current = current_environment_identity()
    previous = _load_state(cfg)
    changed = False
    reason = "initial"

    if previous is None:
        changed = _has_network_state(cfg)
        reason = "missing-state-marker" if changed else "initial"
    else:
        lifecycle_changed = bool(current.get("boot_id") and previous.get("boot_id") and
                                 current.get("boot_id") != previous.get("boot_id"))
        network_fields = ("network", "interface", "kind", "local_ip", "gateway")
        network_changed = any(current.get(k) != previous.get(k) for k in network_fields)
        changed = lifecycle_changed or network_changed
        if lifecycle_changed and network_changed:
            reason = "reboot-and-network-change"
        elif lifecycle_changed:
            reason = "reboot"
        elif network_changed:
            reason = "network-change"
        else:
            reason = "unchanged"

    if changed:
        reset_network_state(cfg)

    _write_state(cfg, current)
    return {
        "changed": changed,
        "reason": reason,
        "current": current,
        "previous": previous,
    }
