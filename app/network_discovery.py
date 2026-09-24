"""Environment-aware local network discovery for ASEP.

The discovery layer is deliberately split into two phases:
1. detect locally connected IPv4 network candidates without probing them;
2. actively discover hosts only after the user starts discovery for a
   detected local candidate.

Host discovery uses Nmap's host-discovery-only mode (``-sn``). No service
scan is started by this module unless the caller explicitly asks for it.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from .nmap_executor import run_nmap, NmapError
from .scope import ScopeError
from .identity_enrichment import enrich_identity, infer_network_role


def _cmd(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return "", str(exc), 1


def _interface_kind(iface: str) -> str:
    if not iface:
        return "unknown"
    try:
        if Path(f"/sys/class/net/{iface}/wireless").exists():
            return "wifi"
        out, _, rc = _cmd(["ip", "-o", "link", "show", "dev", iface])
        if rc == 0 and "loopback" in out.lower():
            return "loopback"
        if iface.startswith(("docker", "br-", "veth", "virbr", "cni", "flannel")):
            return "virtual"
        return "ethernet"
    except Exception:
        return "unknown"


def _dns_servers() -> list[str]:
    servers = []
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m:
                try:
                    ipaddress.ip_address(m.group(1))
                    if m.group(1) not in servers:
                        servers.append(m.group(1))
                except ValueError:
                    pass
    except OSError:
        pass
    if not servers:
        out, _, rc = _cmd(["resolvectl", "dns"], timeout=5)
        if rc == 0:
            for token in re.findall(r"(?:^|\s)(\d+\.\d+\.\d+\.\d+)(?:\s|$)", out):
                if token not in servers:
                    servers.append(token)
    return servers


def local_context() -> dict[str, Any]:
    """Detect local interfaces/routes without sending discovery probes."""
    hostname = socket.gethostname()
    out, _, _ = _cmd(["ip", "-4", "route", "show", "default"])
    gateway = None
    gateway_iface = None
    m = re.search(r"default via (\S+) dev (\S+)", out)
    if m:
        gateway, gateway_iface = m.group(1), m.group(2)

    addr_out, _, _ = _cmd(["ip", "-4", "addr", "show", "scope", "global"])
    local_ips: list[dict[str, Any]] = []
    current_iface = None
    for line in addr_out.splitlines():
        head = re.match(r"\d+:\s+([^:]+):", line)
        if head:
            current_iface = head.group(1).split("@")[0]
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        ip = m.group(1)
        prefix = int(m.group(2))
        try:
            interface = ipaddress.ip_interface(f"{ip}/{prefix}")
            network = str(interface.network)
        except ValueError:
            continue
        local_ips.append({
            "ip": ip,
            "prefix": prefix,
            "network": network,
            "interface": current_iface,
            "kind": _interface_kind(current_iface or ""),
        })

    # De-duplicate network candidates while preserving interface metadata.
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in local_ips:
        key = (item["network"], item.get("interface") or "")
        if key in seen:
            continue
        seen.add(key)
        net = ipaddress.ip_network(item["network"], strict=False)
        candidates.append({
            "network": str(net),
            "interface": item.get("interface"),
            "kind": item.get("kind", "unknown"),
            "local_ip": item["ip"],
            "prefix": item["prefix"],
            "gateway": gateway if item.get("interface") == gateway_iface else None,
            "primary": item.get("interface") == gateway_iface,
            "source": "local-interface",
        })

    # Keep loopback out of active network discovery candidates.
    candidates = [c for c in candidates if c["kind"] != "loopback" and c["network"] != "127.0.0.0/8"]

    return {
        "hostname": hostname,
        "gateway": gateway,
        "gateway_iface": gateway_iface,
        "local_ips": local_ips,
        "candidates": candidates,
    }


def environment_candidates(cfg) -> dict[str, Any]:
    """Return locally detected network candidates; this operation is passive."""
    ctx = local_context()
    configured = set(cfg.get("scope", {}).get("scope", {}).get("networks", []) or [])
    for candidate in ctx["candidates"]:
        candidate["configured"] = candidate["network"] in configured
        candidate["scope_status"] = "CONFIGURED" if candidate["configured"] else "LOCAL-CANDIDATE"
    primary = next((c for c in ctx["candidates"] if c.get("primary")), None)
    if primary is None:
        # A machine can have a usable local interface even when a default
        # route is temporarily absent. Prefer a non-virtual candidate.
        primary = next((c for c in ctx["candidates"] if c.get("kind") in {"ethernet", "wifi"}), None)
    for c in ctx["candidates"]:
        c["is_primary"] = bool(primary and c.get("network") == primary.get("network") and c.get("interface") == primary.get("interface"))
    return {
        "ok": True,
        "timestamp": time.time(),
        "context": {**ctx, "dns_servers": _dns_servers(), "local_ip": primary.get("local_ip") if primary else None},
        "primary": primary,
        "candidates": ctx["candidates"],
        "configured_scope": sorted(configured),
        "active_probe_sent": False,
    }


def neighbor_table():
    out, _, _ = _cmd(["ip", "neigh", "show"])
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        state = parts[-1].upper()
        if state in {"FAILED", "INCOMPLETE"}:
            continue
        mac = None
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                mac = parts[idx + 1]
        iface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        rows.append({"ip": ip, "mac": mac, "interface": iface, "state": state})
    return rows


def _reverse_dns(ip: str) -> str:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.5)
        try:
            return socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return ""


def classify(ip, hostname, gateway, ports=None, is_local=False):
    if is_local:
        return "asep"
    if gateway and ip == gateway:
        return "router"
    text = (hostname or "").lower()
    network_terms = ("router", "gateway", "switch", "sw-", "firewall", "fw-", "ap-", "access-point", "wifi", "wlan", "controller", "core-", "dist-")
    server_terms = ("server", "srv-", "nas", "storage", "dc-", "domain", "ldap", "db-", "database", "vm-")
    workstation_terms = ("desktop", "laptop", "pc-", "workstation", "win-", "mac-", "notebook")
    if any(t in text for t in network_terms):
        return "network"
    if any(t in text for t in server_terms):
        return "server"
    if any(t in text for t in workstation_terms):
        return "workstation"
    ports = ports or []
    services = {str(p.get("service", "")).lower() for p in ports}
    port_ids = {int(p.get("port")) for p in ports if str(p.get("port", "")).isdigit()}
    if {22, 53, 161}.intersection(port_ids) and not {80, 443, 3389, 445}.intersection(port_ids):
        return "infrastructure"
    if {445, 3389, 5985, 5986}.intersection(port_ids) or {"microsoft-ds", "ms-wbt-server", "winrm"}.intersection(services):
        return "workstation"
    if {80, 443}.intersection(port_ids) or {"http", "https"}.intersection(services):
        return "server"
    return "unknown"


def _select_candidate(ctx: dict[str, Any], network: str | None, interface: str | None = None) -> dict[str, Any]:
    candidates = ctx.get("candidates", [])
    if network:
        try:
            requested = ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ScopeError(f"Invalid network candidate: {network}") from exc
        matches = [c for c in candidates if ipaddress.ip_network(c["network"], strict=False) == requested]
    elif interface:
        matches = [c for c in candidates if c.get("interface") == interface]
    else:
        matches = [c for c in candidates if c.get("primary")] or candidates[:1]
    if not matches:
        raise ScopeError("Network bukan jaringan lokal yang sedang terhubung ke ASEP.")
    return matches[0]


def discover(cfg, network: str | None = None, method: str = "auto", interface: str | None = None, reverse_dns: bool = False):
    """Actively discover hosts on one locally detected network candidate."""
    method = (method or "auto").lower()
    if method not in {"auto", "arp", "icmp", "tcp"}:
        raise ScopeError("Discovery method must be auto, arp, icmp, or tcp.")

    ctx = local_context()
    # _select_candidate raises ScopeError when no locally attached network
    # currently matches the request (e.g. interface flapped, DHCP renewed,
    # laptop briefly disconnected between the last environment probe and
    # this discovery run). This is a routine, expected condition for a
    # portable assessment appliance, not an application fault, so it must
    # be normalized into the same {"ok": False, "errors": [...]} contract
    # used below for run_nmap failures rather than raised. Previously this
    # path bypassed that contract, causing the caller's generic exception
    # handler to skip _persist_discovery_result (no evidence/run record,
    # stale cached status) on every recurring automatic discovery cycle.
    try:
        candidate = _select_candidate(ctx, network, interface)
    except ScopeError as exc:
        return {
            "ok": False,
            "timestamp": time.time(),
            "network": {"network": network, "interface": interface},
            "nodes": [],
            "active_hosts": [],
            "errors": [str(exc)],
            "method": method,
        }
    target_network = candidate["network"]
    configured_networks = set(cfg.get("scope", {}).get("scope", {}).get("networks", []) or [])
    candidate["scope_status"] = "IN-SCOPE" if target_network in configured_networks else "LOCAL-CANDIDATE"

    # The explicit local-discovery gate is enforced inside run_nmap. It only
    # accepts a network currently attached to a local interface.
    profile = f"host_discovery_{method}"
    try:
        result = run_nmap(cfg, target_network, profile, local_discovery=True)
    except (ScopeError, NmapError) as exc:
        return {
            "ok": False,
            "timestamp": time.time(),
            "network": candidate,
            "nodes": [],
            "active_hosts": [],
            "errors": [str(exc)],
            "method": method,
        }

    local_ips = {x["ip"] for x in ctx.get("local_ips", [])}
    neighbors = {n["ip"]: n for n in neighbor_table()}
    nodes: list[dict[str, Any]] = []
    active_hosts: list[dict[str, Any]] = []

    for host in result.get("hosts", []):
        ip = next((a for a in host.get("addresses", []) if "." in a), None)
        if not ip:
            continue
        mac = host.get("mac") or neighbors.get(ip, {}).get("mac")
        vendor = host.get("vendor") or ""
        hostname = (host.get("hostnames") or [""])[0]
        # Always enrich identity. reverse_dns controls the Nmap discovery
        # preference, but the local resolver is still used as a fallback.
        identity = enrich_identity(ip, mac, hostname, vendor)
        hostname = identity["hostname"]
        vendor = identity["vendor"]
        role_info = infer_network_role(ip, hostname, vendor, host.get("ports"), ctx.get("gateway"), ip in local_ips)
        role = role_info["role"]
        item = {
            "id": ip,
            "ip": ip,
            "name": hostname or ip,
            "hostname": hostname,
            "role": role,
            "state": host.get("state", "up"),
            "mac": mac,
            "vendor": vendor,
            "interface": candidate.get("interface"),
            "source": "nmap-host-discovery",
            "discovery_method": method,
            "ports": host.get("ports", []),
            "is_local": ip in local_ips,
            "is_gateway": ip == ctx.get("gateway"),
            "scope_status": candidate.get("scope_status", "LOCAL-CANDIDATE"),
            "identity": identity,
            "role_confidence": role_info["confidence"],
            "role_basis": role_info["basis"],
        }
        active_hosts.append(item)
        nodes.append(item)

    # Always surface the local ASEP host even if Nmap filters its response.
    for local in ctx.get("local_ips", []):
        if local.get("network") != target_network:
            continue
        if local["ip"] not in {h["ip"] for h in active_hosts}:
            nodes.append({
                "id": local["ip"], "ip": local["ip"], "name": ctx["hostname"],
                "hostname": ctx["hostname"], "role": "asep", "state": "local",
                "mac": None, "vendor": "", "interface": local.get("interface"),
                "source": "local-interface", "discovery_method": "local",
                "ports": [], "is_local": True, "is_gateway": False,
                "scope_status": candidate.get("scope_status", "LOCAL-CANDIDATE"),
                "identity": enrich_identity(local["ip"], None, ctx["hostname"], ""),
                "role_confidence": "high", "role_basis": "local interface",
            })

    gateway = ctx.get("gateway")
    if gateway and gateway in {c["ip"] for c in active_hosts}:
        for node in nodes:
            if node["ip"] == gateway:
                node["role"] = "Gateway / Router"
                node["is_gateway"] = True
                node["role_confidence"] = "high"
                node["role_basis"] = "default route gateway"

    # Topology is evidence-backed logical topology, not a claim about the
    # physical switch fabric. It combines local routing and ARP neighbor data.
    edge_map = {}
    topology_nodes = []
    active_ips = {h["ip"] for h in active_hosts}
    for n in nodes:
        topology_nodes.append({"id": n["ip"], "role": n.get("role"), "mac": n.get("mac"), "vendor": n.get("vendor")})

    def add_edge(source, target, relation, basis):
        if not source or not target or source == target:
            return
        key = (source, target)
        edge = edge_map.get(key)
        if edge is None:
            edge = {
                "from": source,
                "to": target,
                "relations": [],
                "basis": [],
                "status": "OBSERVED",
            }
            edge_map[key] = edge
        if relation not in edge["relations"]:
            edge["relations"].append(relation)
        if basis not in edge["basis"]:
            edge["basis"].append(basis)

    if gateway and gateway in active_ips:
        for ip in sorted(active_ips - {gateway}):
            add_edge(gateway, ip, "default-gateway", "local routing table")
    for ip, neigh in neighbors.items():
        if ip in active_ips and neigh.get("state") in {"REACHABLE", "STALE", "DELAY", "PROBE"}:
            # ARP neighbor entries are observations made by the ASEP host's
            # local kernel. They are not evidence that the gateway owns the
            # neighbor relationship. Keep the local ASEP IP as the source.
            add_edge(candidate.get("local_ip"), ip, "lan-neighbor", "ARP neighbor table")

    edges = []
    for edge in edge_map.values():
        edge["relation"] = edge["relations"][0] if len(edge["relations"]) == 1 else " + ".join(edge["relations"])
        if len(edge["basis"]) == 1:
            edge["basis"] = edge["basis"][0]
        edges.append(edge)
    topology = {
        "network": target_network, "interface": candidate.get("interface"),
        "local_ip": candidate.get("local_ip"), "gateway": gateway,
        "gateway_interface": ctx.get("gateway_iface"),
        "logical_model": "default-gateway + local-neighbor evidence",
        "nodes": topology_nodes, "edges": edges,
    }

    non_self_hosts = [h for h in active_hosts if not h.get("is_local") and not h.get("is_gateway")]
    network_diagnostic = None
    if len(active_hosts) == 0:
        network_diagnostic = {
            "level": "warning",
            "title": "No hosts found on this network segment",
            "likely_causes": [
                "Captive portal pre-authentication block — most public/guest Wi-Fi blocks nearly all "
                "traffic except to the portal server and DNS until login is completed in a browser.",
                "Client/AP isolation enabled on the access point — deliberately prevents clients from "
                "seeing each other, sometimes even after login. Very common default on guest/hotel/hotspot APs.",
                "Genuinely no other active hosts on this segment right now.",
            ],
            "next_steps": [
                "If the captive portal login isn't complete yet, finish it first, then let discovery re-run.",
                "If this is your own access point: check its admin panel for a \"Client Isolation\" / "
                "\"AP Isolation\" setting and disable it for this test.",
                "If this is not your own network, isolation is a deliberate control of the network owner "
                "and should not be bypassed without their explicit authorization.",
            ],
        }
    elif not non_self_hosts and gateway:
        network_diagnostic = {
            "level": "info",
            "title": "Only the gateway/router is visible — no other clients found",
            "likely_causes": [
                "Client/AP isolation enabled on the access point — each client can reach the gateway/"
                "internet but is deliberately prevented from reaching other clients on the same network.",
                "Genuinely no other active devices on this segment right now.",
            ],
            "next_steps": [
                "If this is your own access point: check its admin panel for a \"Client Isolation\" / "
                "\"AP Isolation\" setting.",
                "If this is not your own network, isolation is a deliberate control of the network owner.",
            ],
        }

    return {
        "ok": True,
        "timestamp": time.time(),
        "network": {**candidate, "local_ip": candidate.get("local_ip"), "gateway": ctx.get("gateway"), "dns_servers": _dns_servers()},
        "method": method,
        "command": result.get("command", []),
        "active_hosts": active_hosts,
        "nodes": nodes,
        "active_count": len(active_hosts),
        "errors": [],
        "scope_status": "LOCAL-CANDIDATE",
        "topology": topology,
        "network_diagnostic": network_diagnostic,
    }
