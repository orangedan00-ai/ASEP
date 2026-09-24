import ipaddress
import socket
from pathlib import Path
import subprocess
import re

class ScopeError(Exception):
    pass

def _networks(cfg):
    return [ipaddress.ip_network(x, strict=False)
            for x in cfg["scope"].get("scope", {}).get("networks", [])]

def _hosts(cfg):
    return set(cfg["scope"].get("scope", {}).get("hosts", []) or [])

def target_in_scope(cfg, target):
    target = target.strip()
    if not target:
        raise ScopeError("Target kosong.")

    if target in _hosts(cfg):
        return True

    try:
        obj = ipaddress.ip_address(target)
        return any(obj in net for net in _networks(cfg))
    except ValueError:
        pass

    try:
        requested_net = ipaddress.ip_network(target, strict=False)
        return any(requested_net.subnet_of(net) for net in _networks(cfg))
    except ValueError:
        pass

    return target in _hosts(cfg)

def _local_ipv4_networks():
    """Detect currently connected IPv4 networks without sending probes."""
    try:
        proc = subprocess.run(
            ["ip", "-4", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    nets = []
    for line in proc.stdout.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        try:
            nets.append(ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}").network)
        except ValueError:
            continue
    return list(dict.fromkeys(nets))

def assert_local_discovery_target(cfg, target):
    """Allow host discovery only against a network attached to a local interface.

    This is intentionally narrower than the normal scope assertion: it does
    not permit arbitrary RFC1918/private ranges. The requested network must
    currently exist on an active local IPv4 interface, and the feature must
    be enabled in config.
    """
    enabled = cfg.get("scope", {}).get("environment_discovery", {}).get("enabled", False)
    if not enabled:
        raise ScopeError("Automatic environment discovery disabled in config/scope.yaml.")
    try:
        requested = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScopeError(f"Invalid local discovery network: {target}") from exc
    local_nets = _local_ipv4_networks()
    if not any(requested == net for net in local_nets):
        raise ScopeError(f"{target} bukan network lokal yang sedang terhubung.")


def assert_local_discovery_host(cfg, target):
    """Allow automatic discovery/service validation for a host on a directly connected local IPv4 network."""
    enabled = cfg.get("scope", {}).get("environment_discovery", {}).get("enabled", False)
    if not enabled:
        raise ScopeError("Automatic environment discovery disabled in config/scope.yaml.")
    try:
        obj = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ScopeError(f"Invalid local discovery host: {target}") from exc
    if obj.is_loopback or obj.is_unspecified or obj.is_multicast:
        raise ScopeError(f"Invalid local discovery host: {target}")
    local_nets = _local_ipv4_networks()
    if not any(obj in net for net in local_nets):
        raise ScopeError(f"{target} bukan host pada network lokal yang sedang terhubung.")

def assert_target(cfg, target):
    if not target_in_scope(cfg, target):
        raise ScopeError(
            f"Target '{target}' berada di luar scope. "
            "Tambahkan secara eksplisit ke config/scope.yaml."
        )

def allowed_targets(cfg):
    out = []
    out.extend(cfg["scope"].get("scope", {}).get("networks", []) or [])
    out.extend(cfg["scope"].get("scope", {}).get("hosts", []) or [])
    return out
