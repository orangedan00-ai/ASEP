from pathlib import Path
import json
import time
import os
import platform
import re
import shutil
import subprocess
import socket
import threading
import time
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request, Response
import psutil

from .audit import log
from .session_intelligence import probe_session as si_probe_session, create_demo_account as si_create_demo, run_demo_cleanup as si_run_cleanup
from .db import add_evidence, get_evidence, list_evidence, connect, upsert_target, list_targets, create_discovery_run, finish_discovery_run, list_discovery_runs, create_service_scan, finish_service_scan, add_service_inventory, list_service_inventory, latest_service_scan, latest_service_scan_xml, init_db, create_demo_account as db_create_demo, list_demo_accounts, get_demo_account, record_demo_cleanup
from .llm import LLMRouter
from .nmap_executor import run_nmap, PROFILES, NmapError
from .scope import ScopeError, allowed_targets, assert_target
from .shell_executor import run_shell, ShellError
from .privilege import current_user, run_with_sudo, PrivilegeError
from .wireless import WirelessError, interfaces as wifi_interfaces, scan_nmcli, scan_iw, link as wifi_link, capabilities as wifi_capabilities, run_chain as wifi_chain
from .wireless_attack_path import build_attack_paths
from .network_discovery import discover as discover_network, environment_candidates, local_context
from .identity_enrichment import enrich_identity, infer_asset_type, infer_network_role
from .intelligence import IntelligenceEngine
from .tool_registry import inventory as tool_inventory
from .tool_orchestrator import run_profile, plan_for_target, ToolError
from .internet_research import nvd_cves
from .exploit_candidates import find_target_candidates
from .assessment_engine import run_chain, AssessmentError
from .self_heal import health as self_health, retry_once
from .windows_fingerprint import fingerprint, WindowsFingerprintError
from .metasploit import search_modules, check_module, run_module, module_options, module_info, module_check_supported, module_platforms, _platform_compatible, list_sessions, refresh_session, remote_sessions, interact_session, MetasploitError
from .adaptive_reasoning import build_hypotheses, alternative_paths, correlate
from .deception import assess as assess_deception
from .skill_library import inventory as skill_inventory
from .skill_prompts import inventory as skill_prompts_inventory
from .skill_registry import inventory as skill_registry_inventory, seed_builtin_skills
from .provider_health import ProviderHealth
from .metasploit_universal import TargetFingerprint, MetasploitModule, match_modules, build_validation_plan
from .post_session_api import build_post_session_advice
from .target_path import CandidateAsset, passive_deep_dive
from .capability_router import SecurityObjective, recommend_capabilities
from .replanner import PlanState, Replanner
from .self_heal import repair_with_patch
from .version import VERSION
from .config import persist_env_var
from .ux import dashboard as ux_dashboard, target_objects as ux_targets, evidence_objects as ux_evidence, finding_objects as ux_findings, recommendation_objects as ux_recommendations, activity as ux_activity, intelligence_summary as ux_intelligence_summary

def create_app(cfg):
    try:
        init_db(cfg)
        seed_builtin_skills(cfg)
    except Exception as exc:
        print(f"ASEP skill registry setup warning: {exc}")
    health_monitor = ProviderHealth(cfg)
    health_monitor.start()
    monitor = {
        "started_at": time.time(),
        "active": None,
        "last_activity": "ASEP initialized",
        "last_activity_at": datetime.now(timezone.utc).isoformat(),
    }
    monitor_lock = threading.Lock()
    network_map = {"status": "idle", "data": None, "started_at": None, "finished_at": None, "error": None}
    network_map_lock = threading.Lock()
    discovery_state = {"status": "idle", "data": None, "run_id": None, "started_at": None, "finished_at": None, "error": None}
    discovery_lock = threading.Lock()
    awareness = {"last_started": 0.0, "last_network": None, "service_queue": [], "service_running": False}
    awareness_lock = threading.Lock()
    service_lock = threading.Lock()
    deep_scan = {"status": "idle", "network": None, "started_at": None, "finished_at": None,
                 "current": None, "total": 0, "completed": 0, "hosts": [], "ports": 0,
                 "services": 0, "error": None, "reason": None, "auto": False,
                 "scanned_hosts": [], "failed_hosts": [], "failed_at": {}, "current_started_at": None,
                 "last_progress_at": None, "elapsed_sec": 0,
                 "host_timeout_sec": 300, "process_timeout_sec": 360}
    deep_scan_lock = threading.Lock()

    def set_activity(name, target="", status="RUNNING"):
        with monitor_lock:
            monitor["active"] = {"name": name, "target": target, "status": status, "since": time.time()}
            monitor["last_activity"] = f"{name} {target}".strip()
            monitor["last_activity_at"] = datetime.now(timezone.utc).isoformat()

    def clear_activity():
        with monitor_lock:
            monitor["active"] = None

    def recent_audit(limit=12):
        try:
            con = connect(cfg)
            rows = con.execute(
                "SELECT id,created_at,action,target,status,details FROM audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            con.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    app = Flask(
        __name__,
        template_folder=str(Path(cfg["root"]) / "templates"),
        static_folder=str(Path(cfg["root"]) / "static"),
    )

    llm = LLMRouter(cfg)
    intelligence = IntelligenceEngine(cfg, llm)

    def _is_loopback_bind(host):
        return host in {"127.0.0.1", "localhost", "::1"}

    @app.before_request
    def _minimal_auth_guard():
        # Localhost is the default and remains passwordless for a convenient
        # single-user lab workflow. Any non-loopback bind must use HTTP Basic
        # Auth; otherwise ASEP would expose state-changing APIs on the LAN.
        if _is_loopback_bind(cfg.get("host", "127.0.0.1")):
            return None
        username = str(cfg.get("auth_user") or "asep")
        password = str(cfg.get("auth_password") or "")
        auth = request.authorization
        if not password or not auth or auth.username != username or auth.password != password:
            return Response("Authentication required\n", 401, {"WWW-Authenticate": 'Basic realm="ASEP"'})
        return None

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
    def status():
        with monitor_lock:
            active = dict(monitor["active"]) if monitor["active"] else None
            if active:
                active["elapsed"] = round(time.time() - active["since"], 1)
        return jsonify({
            "name": "ASEP",
            "version": VERSION,
            "skills": skill_inventory(),
            "llm_mode": llm.mode(),
            "scope": allowed_targets(cfg),
            "profiles": list(PROFILES.keys()),
            "tool_inventory": tool_inventory(),
            "current_activity": (active.get("action", "") + " → " + active.get("target", "")) if active else "",
            "active": bool(active),
        })

    @app.get("/api/monitor")
    def monitor_status():
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        with monitor_lock:
            active = dict(monitor["active"]) if monitor["active"] else None
            if active:
                active["elapsed"] = round(time.time() - active["since"], 1)
        return jsonify({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": vm.percent,
            "memory_used_mb": round(vm.used / 1024 / 1024),
            "memory_total_mb": round(vm.total / 1024 / 1024),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / 1024**3, 1),
            "disk_total_gb": round(disk.total / 1024**3, 1),
            "net_sent_mb": round(net.bytes_sent / 1024**2, 2),
            "net_recv_mb": round(net.bytes_recv / 1024**2, 2),
            "active": active,
            "last_activity": monitor["last_activity"],
            "last_activity_at": monitor["last_activity_at"],
            "audit": recent_audit(),
        })


    def _ensure_auto_awareness():
        """Ensure lightweight local network awareness runs on its cadence.

        Dashboard reads are also the trigger for the existing continuous
        awareness loop. Keep this lightweight: it only checks the current
        environment candidate and starts host discovery when the previous
        discovery is idle/stale. Comprehensive service scanning remains
        governed by the deep-scan workflow and is not repeated here.
        """
        now = time.time()
        interval = 30.0
        with awareness_lock:
            if now - float(awareness.get("last_started") or 0.0) < interval:
                return False
        try:
            env = environment_candidates(cfg)
            primary = env.get("primary") or {}
            network = str(primary.get("network") or "").strip()
            interface = str(primary.get("interface") or "").strip() or None
            if not network:
                return False
        except Exception as exc:
            log(cfg, "automatic_network_awareness", "environment", "ERROR", str(exc))
            return False

        with network_map_lock:
            if network_map.get("status") == "running":
                return False
            finished_at = network_map.get("finished_at")
            age = (now - finished_at) if finished_at else None
            if network_map.get("status") == "ready" and age is not None and age < interval:
                return False
            network_map["status"] = "running"
            network_map["started_at"] = now
            network_map["finished_at"] = None
            network_map["error"] = None

        with awareness_lock:
            awareness["last_started"] = now
            awareness["last_network"] = network

        threading.Thread(
            target=_network_discovery_worker,
            kwargs={"network": network, "method": "auto", "interface": interface},
            daemon=True,
            name="asep-auto-awareness",
        ).start()
        log(cfg, "automatic_network_awareness", network, "STARTED", f"interface={interface or 'auto'}")
        return True

    def _auto_service_scan_worker(hosts):
        """Sequentially service-scan newly observed local hosts with a small queue."""
        try:
            while True:
                with awareness_lock:
                    if not awareness["service_queue"]:
                        awareness["service_running"] = False
                        break
                    target = awareness["service_queue"].pop(0)
                try:
                    set_activity("Automatic service discovery", target)
                    result = run_nmap(cfg, target, "service", local_discovery=True)
                    host = next((h for h in result.get("hosts", []) if target in (h.get("addresses") or [])), result.get("hosts", [{}])[0] if result.get("hosts") else {})
                    observed = []
                    for p in host.get("ports", []) or []:
                        state = str(p.get("state") or "").lower()
                        if state in {"open", "open|filtered"} or p.get("service"):
                            observed.append({**p, "detection": "Nmap -sV"})
                    existing = next((x for x in list_targets(cfg, 500) if str(x.get("address")) == target), None)
                    ident = enrich_identity(target, host.get("mac"), (host.get("hostnames") or [""])[0], host.get("vendor", ""))
                    role_info = infer_network_role(target, ident.get("hostname"), ident.get("vendor"), observed, local_context().get("gateway"), False)
                    upsert_target(cfg, {
                        "address": target, "name": ident.get("hostname") or (existing or {}).get("name") or target,
                        "role": role_info.get("role", (existing or {}).get("role", "unknown")), "state": host.get("state", "up"),
                        "scope_status": "LOCAL-CANDIDATE", "mac": ident.get("mac_normalized"), "vendor": ident.get("vendor"),
                        "interface": (existing or {}).get("interface"), "source": (existing or {}).get("source", "network-discovery"),
                        "metadata": {**((existing or {}).get("metadata") or {}), "hostname": ident.get("hostname", ""), "vendor": ident.get("vendor", ""), "identity": ident, "ports": observed}
                    })
                    payload = {"target": target, "profile": "service", "scanner": "nmap", "method": "-sV --top-ports 100", "ports": observed, "port_count": len(observed)}
                    add_evidence(cfg, "service_scan", target, json.dumps({"services": len(observed), "automatic": True, "profile": "service"}), json.dumps(payload, ensure_ascii=False))
                    log(cfg, "automatic_service_discovery", target, "OK", f"services={len(observed)}")
                except (ScopeError, NmapError) as exc:
                    add_evidence(cfg, "service_scan", target, "Automatic service discovery blocked", json.dumps({"target": target, "error": str(exc), "automatic": True}, ensure_ascii=False))
                    log(cfg, "automatic_service_discovery", target, "BLOCKED", str(exc))
                except Exception as exc:
                    log(cfg, "automatic_service_discovery", target, "ERROR", str(exc))
                finally:
                    clear_activity()
        finally:
            with awareness_lock:
                awareness["service_running"] = False

    def _queue_new_host_service_scans(hosts):
        targets = [str(h.get("ip") or "").strip() for h in hosts if h.get("ip")]
        if not targets:
            return
        with awareness_lock:
            for target in targets:
                if target not in awareness["service_queue"]:
                    awareness["service_queue"].append(target)
            if awareness["service_running"]:
                return
            awareness["service_running"] = True
        threading.Thread(target=_auto_service_scan_worker, args=(targets,), daemon=True, name="asep-auto-service").start()

    def _mark_missing_hosts_offline(network, active_ips):
        """Mark previously known assets in the current local network offline without changing last_seen."""
        try:
            con = connect(cfg)
            rows = con.execute("SELECT address,metadata,state FROM targets").fetchall()
            active = set(active_ips)
            import ipaddress as _ipaddress, json as _json
            net = _ipaddress.ip_network(str(network), strict=False)
            changed = 0
            for row in rows:
                address = str(row["address"] or "")
                try:
                    if _ipaddress.ip_address(address) not in net or address in active:
                        continue
                except ValueError:
                    continue
                if str(row["state"] or "").lower() == "offline":
                    continue
                con.execute("UPDATE targets SET state=? WHERE address=?", ("offline", address))
                changed += 1
            con.commit(); con.close()
            return changed
        except Exception:
            return 0

    def _persist_discovery_result(result, run_id=None):
        active = result.get("active_hosts", []) or []
        new_count = 0
        known_count = 0
        new_hosts = []
        existing_map = {str(x.get("address")): x for x in list_targets(cfg, 500)}
        active_ips = {str(h.get("ip")) for h in active if h.get("ip")}
        offline_count = _mark_missing_hosts_offline(result.get("network", {}).get("network", ""), active_ips)
        for host in active:
            prior = existing_map.get(str(host.get("ip")))
            old_mac = str((prior or {}).get("mac") or "").replace(":", "").lower()
            new_mac = str(host.get("mac") or "").replace(":", "").lower()
            identity_changed = bool(old_mac and new_mac and old_mac != new_mac)
            prior_md = (prior or {}).get("metadata") or {}
            discovery_md = {
                **prior_md,
                "network": result.get("network", {}).get("network"),
                "method": result.get("method"),
                "ports": host.get("ports", []),
                "hostname": host.get("hostname", ""),
            }
            # Continuous host discovery must never erase completed deep-scan
            # state, OS evidence, identity enrichment, or scan timestamps.
            # Discovery is a refresh layer; deep service inventory is authoritative.
            outcome = upsert_target(cfg, {
                "address": host.get("ip"),
                "name": host.get("name") or host.get("ip"),
                "role": host.get("role", "unknown"),
                "state": host.get("state", "up"),
                "scope_status": "IN-SCOPE" if host.get("scope_status") == "IN-SCOPE" else "LOCAL-CANDIDATE",
                "mac": host.get("mac"),
                "vendor": host.get("vendor"),
                "interface": host.get("interface"),
                "source": host.get("source", "nmap-host-discovery"),
                "metadata": discovery_md,
            })
            if outcome["created"]:
                new_count += 1
                new_hosts.append(host)
            elif identity_changed:
                new_count += 1
                new_hosts.append(host)
            else:
                known_count += 1
        result["new_count"] = new_count
        result["known_count"] = known_count
        result["active_count"] = len(active)
        result["new_hosts"] = [h.get("ip") for h in new_hosts]
        result["offline_count"] = offline_count
        if cfg.get("auto_deep_scan_enabled", True):
            _maybe_auto_deep_scan(result.get("network", {}).get("network", ""), active)
        elif new_hosts:
            _queue_new_host_service_scans(new_hosts)
        if run_id:
            finish_discovery_run(cfg, run_id, "READY" if result.get("ok") else "ERROR",
                                 result["active_count"], new_count, known_count,
                                 "" if result.get("ok") else "; ".join(result.get("errors", [])), result)
        add_evidence(
            cfg, "network_discovery", result.get("network", {}).get("network", "environment"),
            f"{len(active)} active host(s), {new_count} new, {known_count} known",
            json.dumps(result, ensure_ascii=False),
        )
        return result

    def _network_discovery_worker(network=None, method="auto", interface=None, reverse_dns=False, run_id=None):
        with network_map_lock:
            network_map["status"] = "running"
            network_map["started_at"] = time.time()
            network_map["finished_at"] = None
            network_map["error"] = None
        set_activity("Network host discovery", network or interface or "local environment")
        try:
            result = discover_network(cfg, network=network, method=method, interface=interface, reverse_dns=reverse_dns)
            result = _persist_discovery_result(result, run_id)
            with network_map_lock:
                network_map["status"] = "ready" if result.get("ok") else "error"
                network_map["data"] = result
                network_map["finished_at"] = time.time()
                network_map["error"] = "; ".join(result.get("errors", [])) if not result.get("ok") else None
            with discovery_lock:
                discovery_state["status"] = "ready" if result.get("ok") else "error"
                discovery_state["data"] = result
                discovery_state["finished_at"] = time.time()
                discovery_state["error"] = "; ".join(result.get("errors", [])) if not result.get("ok") else None
            log(cfg, "network_host_discovery", result.get("network", {}).get("network", "environment"), "OK" if result.get("ok") else "ERROR",
                f"active={result.get('active_count', 0)} new={result.get('new_count', 0)}")
        except Exception as exc:
            if run_id:
                finish_discovery_run(cfg, run_id, "ERROR", error=str(exc))
            with network_map_lock:
                network_map["status"] = "error"
                network_map["error"] = str(exc)
                network_map["finished_at"] = time.time()
            with discovery_lock:
                discovery_state["status"] = "error"
                discovery_state["error"] = str(exc)
                discovery_state["finished_at"] = time.time()
            log(cfg, "network_host_discovery", network or interface or "environment", "ERROR", str(exc))
        finally:
            clear_activity()

    def _start_deep_scan_batch(network, targets, reason="automatic", force=False):
        """Start a comprehensive TCP all-port inventory batch for local live hosts."""
        targets = sorted({str(x).strip() for x in targets if str(x).strip()},
                         key=lambda x: __import__("ipaddress").ip_address(x))
        if not targets:
            return False, "No live hosts available."
        with deep_scan_lock:
            if deep_scan["status"] == "running":
                return False, "Comprehensive scan is already running."
            if deep_scan.get("network") != network:
                deep_scan["scanned_hosts"] = []
                deep_scan["failed_at"] = {}
            scanned = set(deep_scan.get("scanned_hosts") or [])
            failed_at = dict(deep_scan.get("failed_at") or {})
            if force:
                batch = targets
                deep_scan["scanned_hosts"] = []
                failed_at = {}
            else:
                now = time.time()
                # Do not immediately retry a host that just timed out/failed;
                # this prevents continuous discovery from creating an endless
                # retry loop. Manual RESCAN ALL SERVICES always overrides it.
                batch = [t for t in targets if t not in scanned and
                         (now - float(failed_at.get(t, 0) or 0)) >= 1800]
            if not batch:
                return False, "All currently live hosts already have comprehensive scan evidence."
            now = time.time()
            deep_scan.update({
                "status": "running", "network": network, "started_at": now,
                "finished_at": None, "current": None, "current_started_at": None,
                "last_progress_at": now, "elapsed_sec": 0,
                "total": len(batch), "completed": 0,
                "hosts": [], "failed_hosts": [], "failed_at": failed_at, "ports": 0, "services": 0, "error": None,
                "reason": reason, "auto": reason == "automatic",
            })
        threading.Thread(target=_deep_scan_worker, args=(network, batch, reason),
                         daemon=True, name="asep-deep-network-scan").start()
        return True, f"Comprehensive scan started for {len(batch)} live host(s)."

    def _maybe_auto_deep_scan(network, active_hosts):
        if not cfg.get("auto_deep_scan_enabled", True):
            return
        targets=[str(h.get("ip") or "").strip() for h in (active_hosts or [])
                 if h.get("ip") and str(h.get("state") or "up").lower() in {"up","local","reachable"}]
        if not targets:
            return
        started, msg = _start_deep_scan_batch(network, targets, reason="automatic", force=False)
        if started:
            log(cfg, "automatic_deep_network_scan", network, "STARTED", f"hosts={len(targets)}")

    def _deep_scan_worker(network, targets, reason="manual"):
        """Parallel deep scan: up to cfg['deep_scan_concurrency'] hosts at once.
        Each host runs its own thread; results accumulate into deep_scan state
        under deep_scan_lock. The worker exits when all hosts are done.
        Stage 2 upgrade: concurrent instead of serial, with configurable
        per-host timeout aligned to the Nmap --host-timeout profile value.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        concurrency = max(1, int(cfg.get("deep_scan_concurrency", 3)))
        host_timeout = int(cfg.get("deep_scan_host_timeout", 480))

        # Patch run_nmap timeout dynamically for the host_timeout config value
        # so the subprocess cap and the Nmap --host-timeout never conflict.
        # We monkey-patch via a local wrapper rather than touching nmap_executor.py
        # globally, to avoid breaking anything else that calls run_nmap.
        original_timeout = 360

        def scan_one(target):
            current_started = time.time()
            with deep_scan_lock:
                deep_scan["current"] = target
                deep_scan["current_started_at"] = current_started
                deep_scan["last_progress_at"] = current_started
                deep_scan["elapsed_sec"] = int(current_started - (deep_scan.get("started_at") or current_started))
            set_activity("Comprehensive service/port scan", target)
            scan_id = None
            try:
                started_iso = datetime.now(timezone.utc).isoformat()
                scan_id = create_service_scan(cfg, target, network, "deep_full", reason, [], started_at=started_iso)
                import app.nmap_executor as _ne
                orig = _ne.subprocess.run
                def patched_run(*a, **kw):
                    kw["timeout"] = host_timeout
                    return orig(*a, **kw)
                _ne.subprocess.run = patched_run
                try:
                    result = run_nmap(cfg, target, "deep_full", local_discovery=True)
                finally:
                    _ne.subprocess.run = orig
                con_cmd = result.get("command") or []
                con = connect(cfg)
                con.execute("UPDATE service_scans SET command=? WHERE id=?", (json.dumps(con_cmd, ensure_ascii=False), scan_id))
                con.commit(); con.close()
                host = next((h for h in result.get("hosts", []) if target in (h.get("addresses") or [])), None)
                if host is None and result.get("hosts"):
                    host = result["hosts"][0]
                host = host or {"state": "unknown", "ports": []}
                observed = []
                for p in host.get("ports", []) or []:
                    state = str(p.get("state") or "").lower()
                    if state in {"open", "open|filtered"} or p.get("service"):
                        observed.append({**p, "detection": "Nmap deep_full", "scan_scope": "TCP all ports"})
                existing = next((x for x in list_targets(cfg, 500) if str(x.get("address")) == target), None)
                ident = enrich_identity(target, host.get("mac"), (host.get("hostnames") or [""])[0], host.get("vendor", ""))
                role_info = infer_network_role(target, ident.get("hostname"), ident.get("vendor"), observed, local_context().get("gateway"), False)
                upsert_target(cfg, {
                    "address": target, "name": ident.get("hostname") or (existing or {}).get("name") or target,
                    "role": role_info.get("role", (existing or {}).get("role", "unknown")), "state": host.get("state", "up"),
                    "scope_status": (existing or {}).get("scope_status", "LOCAL-CANDIDATE"), "mac": ident.get("mac_normalized"),
                    "vendor": ident.get("vendor"), "interface": (existing or {}).get("interface"),
                    "source": (existing or {}).get("source", "deep-network-scan"),
                    "metadata": {**((existing or {}).get("metadata") or {}), "hostname": ident.get("hostname", ""),
                                 "vendor": ident.get("vendor", ""), "identity": ident, "ports": observed,
                                 "os_detection": host.get("os_detection") or {},
                                 "deep_scan": True, "deep_scan_at": datetime.now(timezone.utc).isoformat(),
                                 "deep_scan_scope": "TCP 1-65535 + Nmap OS detection"}})
                service_count = len([p for p in observed if p.get("service")])
                add_service_inventory(cfg, scan_id, target, observed, source="nmap-deep-full")
                finish_service_scan(cfg, scan_id, "COMPLETE", raw_xml=result.get("raw_xml", ""), port_count=len(observed), service_count=service_count)
                payload = {"target": target, "profile": "deep_full", "scanner": "nmap",
                           "method": "-sT -p- -sV --version-all --allports --reason -O --osscan-guess",
                           "host_state": host.get("state", "unknown"), "ports": observed,
                           "port_count": len(observed), "service_count": service_count,
                           "comprehensive": True, "scope": network, "reason": reason}
                add_evidence(cfg, "deep_service_scan", target,
                             json.dumps({"services": service_count, "ports": len(observed), "comprehensive": True, "scan_reason": reason}),
                             json.dumps(payload, ensure_ascii=False))
                return {"target": target, "ports": len(observed), "services": service_count,
                        "state": host.get("state", "unknown"), "status": "complete", "os": host.get("os_detection", {}).get("matches", [{}])[0].get("name", "") if host.get("os_detection", {}).get("matches") else ""}
            except (ScopeError, NmapError) as exc:
                try:
                    if scan_id: finish_service_scan(cfg, scan_id, "FAILED", error=str(exc))
                except Exception:
                    pass
                log(cfg, "deep_network_scan", target, "BLOCKED", str(exc))
                return {"target": target, "ports": 0, "services": 0, "state": "scan-blocked", "status": "failed", "error": str(exc)}
            except Exception as exc:
                try:
                    if scan_id: finish_service_scan(cfg, scan_id, "FAILED", error=str(exc))
                except Exception:
                    pass
                log(cfg, "deep_network_scan", target, "ERROR", str(exc))
                return {"target": target, "ports": 0, "services": 0, "state": "error", "status": "failed", "error": str(exc)}

        completed_count = 0
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="asep-deepscan") as pool:
            futures = {pool.submit(scan_one, t): t for t in targets}
            for fut in as_completed(futures):
                entry = fut.result()
                completed_count += 1
                now = time.time()
                with deep_scan_lock:
                    deep_scan["hosts"].append(entry)
                    if entry.get("status") == "failed":
                        deep_scan["failed_hosts"].append(entry)
                        deep_scan["failed_at"][entry["target"]] = now
                    else:
                        deep_scan["ports"] += entry.get("ports", 0)
                        deep_scan["services"] += entry.get("services", 0)
                        if entry["target"] not in deep_scan["scanned_hosts"]:
                            deep_scan["scanned_hosts"].append(entry["target"])
                    deep_scan["completed"] = completed_count
                    deep_scan["last_progress_at"] = now
                    deep_scan["elapsed_sec"] = int(now - (deep_scan.get("started_at") or now))

        now = time.time()
        with deep_scan_lock:
            failed = deep_scan.get("failed_hosts", [])
            deep_scan["status"] = "ready_with_errors" if failed else "ready"
            deep_scan["finished_at"] = now
            deep_scan["elapsed_sec"] = int(now - (deep_scan.get("started_at") or now))
        log(cfg, "deep_network_scan_complete", network, "OK",
            f"completed={completed_count} failed={len(deep_scan.get('failed_hosts', []))} concurrency={concurrency}")
        try:
            with network_map_lock:
                nm = network_map.get("data") or {}
            targets_full = ux_targets(cfg, nm)
            context = f"Deep scan complete on {network}. {completed_count} hosts scanned. " + \
                      " ".join(f"{h['target']} ({h.get('services',0)} services, {h.get('ports',0)} ports)" for h in deep_scan.get("hosts", []) if h.get("status") == "complete")
            llm.reason_with_skill(context, skill_ids=["asset_service_intelligence", "vulnerability_correlation"], _health=health_monitor)
        except Exception:
            pass

    @app.get("/api/deep-scan/status")
    def deep_scan_status():
        with deep_scan_lock:
            return jsonify({"ok": True, **dict(deep_scan)})

    @app.post("/api/deep-scan/start")
    def deep_scan_start():
        body = request.get_json(silent=True) or {}
        confirmed = bool(body.get("confirm_local_scope", False))
        if not confirmed:
            return jsonify({"ok": False, "error": "Explicitly confirm the currently detected local network before a comprehensive scan."}), 400
        try:
            env = environment_candidates(cfg)
            primary = env.get("primary")
            if not primary or not primary.get("network"):
                raise ScopeError("Tidak ada local network yang terdeteksi.")
            network = primary["network"]
            net = __import__("ipaddress").ip_network(network, strict=False)
            live = []
            for t in list_targets(cfg, 500):
                addr = str(t.get("address") or "").strip()
                state = str(t.get("state") or "").lower()
                try:
                    if __import__("ipaddress").ip_address(addr) in net and state in {"up", "local", "reachable"}:
                        live.append(addr)
                except ValueError:
                    continue
            live = sorted(set(live), key=lambda x: __import__("ipaddress").ip_address(x))
            if not live:
                return jsonify({"ok": False, "error": "Belum ada live host inventory. Tunggu automatic discovery selesai lalu mulai deep scan."}), 400
            started, message = _start_deep_scan_batch(network, live, reason="manual", force=True)
            with deep_scan_lock:
                state = dict(deep_scan)
            return jsonify({"ok": True, "status": state.get("status"), "network": network,
                            "targets": live, "count": len(live), "started": started, "message": message})
        except ScopeError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    @app.get("/api/environment")
    def environment_api():
        try:
            return jsonify(environment_candidates(cfg))
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    @app.get("/api/network-discovery/status")
    def network_discovery_status():
        with discovery_lock:
            return jsonify({"ok": True, **dict(discovery_state)})

    @app.get("/api/network-discovery/history")
    def network_discovery_history():
        return jsonify({"ok": True, "runs": list_discovery_runs(cfg, 50)})

    @app.post("/api/network-discovery/start")
    def network_discovery_start():
        body = request.get_json(silent=True) or {}
        network = str(body.get("network", "")).strip() or None
        interface = str(body.get("interface", "")).strip() or None
        method = str(body.get("method", "auto")).strip().lower()
        reverse_dns = bool(body.get("reverse_dns", False))
        confirmed = bool(body.get("confirm_local_scope", False))
        if not confirmed:
            return jsonify({"ok": False, "error": "Explicitly confirm the detected local network before active discovery."}), 400
        if method not in {"auto", "arp", "icmp", "tcp"}:
            return jsonify({"ok": False, "error": "Invalid discovery method."}), 400
        try:
            # Validate the candidate before creating a run or launching a thread.
            probe = environment_candidates(cfg)
            candidates = probe.get("candidates", [])
            chosen = next((c for c in candidates if (network and c["network"] == network) or (not network and interface and c.get("interface") == interface)), None)
            if chosen is None:
                chosen = probe.get("primary") if not network and not interface else None
            if not chosen:
                raise ScopeError("Pilih network/interface yang sedang terhubung ke ASEP.")
            run_id = create_discovery_run(cfg, chosen["network"], chosen.get("interface"), method)
            with discovery_lock:
                discovery_state.update({"status": "running", "data": None, "run_id": run_id, "started_at": time.time(), "finished_at": None, "error": None})
            with network_map_lock:
                network_map["status"] = "running"
            threading.Thread(target=_network_discovery_worker, kwargs={"network": chosen["network"], "method": method, "interface": chosen.get("interface"), "reverse_dns": reverse_dns, "run_id": run_id}, daemon=True).start()
            return jsonify({"ok": True, "run_id": run_id, "status": "running", "network": chosen})
        except ScopeError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except Exception:
            return jsonify({"ok": False, "error": "Unable to start network discovery."}), 500

    @app.get("/api/network-map")
    def network_map_status():
        refresh = request.args.get("refresh", "0") == "1"
        with network_map_lock:
            status = network_map["status"]
            age = (time.time() - network_map["finished_at"]) if network_map.get("finished_at") else None
            should_start = refresh or status in {"idle", "error"} or (status == "ready" and age is not None and age > 30)
            if should_start and network_map["status"] != "running":
                threading.Thread(target=_network_discovery_worker, kwargs={"method": "auto"}, daemon=True).start()
            snapshot = dict(network_map)
        if snapshot.get("data") is not None:
            snapshot["data"] = dict(snapshot["data"])
        return jsonify(snapshot)

    @app.get("/api/wireless/interfaces")
    def wireless_interfaces():
        try:
            return jsonify({"ok": True, **wifi_interfaces()})
        except WirelessError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.post("/api/wireless/scan")
    def wireless_scan():
        body = request.get_json(silent=True) or {}
        iface = str(body.get("interface", "")).strip()
        method = str(body.get("method", "nmcli")).strip().lower()
        try:
            set_activity("Wireless discovery", iface or "all Wi-Fi interfaces")
            if method == "iw":
                if not iface:
                    raise WirelessError("interface is required for iw scan")
                result = scan_iw(iface)
            else:
                result = scan_nmcli()
            target = iface or "wireless"
            add_evidence(cfg, "wireless", target, json.dumps({"method": result.get("method"), "aps": len(result.get("aps", []))}), json.dumps(result, ensure_ascii=False))
            log(cfg, "wireless_scan", target, "OK", method)
            clear_activity()
            return jsonify({"ok": True, **result})
        except WirelessError as e:
            clear_activity(); log(cfg, "wireless_scan", iface or "wireless", "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception:
            clear_activity(); log(cfg, "wireless_scan", iface or "wireless", "ERROR", "internal error")
            return jsonify({"ok": False, "error": "Internal error"}), 500

    @app.post("/api/wireless/connect")
    def wireless_connect():
        body = request.get_json(silent=True) or {}
        ssid = str(body.get("ssid", "")).strip()
        iface = str(body.get("interface", "")).strip()
        password = body.get("password")
        password = str(password) if password is not None else None
        if not ssid or len(ssid) > 255:
            return jsonify({"ok": False, "error": "Invalid SSID"}), 400
        if iface and not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface):
            return jsonify({"ok": False, "error": "Invalid wireless interface"}), 400
        try:
            set_activity("Wireless connect", ssid)
            # Prefer an existing NetworkManager profile so the user can reconnect
            # without entering credentials again.
            con_out = subprocess.run(
                ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
                capture_output=True, text=True, timeout=15
            )
            saved = False
            for line in con_out.stdout.splitlines():
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[0] == ssid and parts[1] == "802-11-wireless":
                    cmd = ["nmcli", "connection", "up", "id", ssid]
                    if iface:
                        cmd += ["ifname", iface]
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if p.returncode == 0:
                        saved = True
                        result = {"ok": True, "connected": True, "ssid": ssid, "interface": iface, "method": "saved-profile", "message": (p.stdout or "Connected").strip()}
                    else:
                        raise WirelessError((p.stderr or p.stdout or "Connection failed").strip())
                    break
            if not saved:
                # Determine whether this is an open AP before allowing a passwordless connect.
                scan = scan_nmcli()
                ap = next((x for x in scan.get("aps", []) if x.get("ssid") == ssid), None)
                security = str((ap or {}).get("security", "")).strip()
                if security and security.upper() not in {"--", "NONE", "OPEN"} and not password:
                    clear_activity()
                    return jsonify({"ok": False, "requires_password": True, "ssid": ssid, "security": security, "error": "This network requires a Wi-Fi password."}), 400
                cmd = ["nmcli", "device", "wifi", "connect", ssid]
                if iface:
                    cmd += ["ifname", iface]
                if password:
                    cmd += ["password", password]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if p.returncode != 0:
                    raise WirelessError((p.stderr or p.stdout or "Connection failed").strip())
                result = {"ok": True, "connected": True, "ssid": ssid, "interface": iface, "method": "nmcli", "message": (p.stdout or "Connected").strip()}
            add_evidence(cfg, "wireless_connect", ssid, "Wi-Fi connection initiated from ASEP", json.dumps({"interface": iface, "method": result.get("method")}, ensure_ascii=False))
            log(cfg, "wireless_connect", ssid, "OK", result.get("method", "nmcli"))
            clear_activity()
            return jsonify(result)
        except (WirelessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            clear_activity(); log(cfg, "wireless_connect", ssid or "wireless", "ERROR", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:
            clear_activity(); log(cfg, "wireless_connect", ssid or "wireless", "ERROR", "internal error")
            return jsonify({"ok": False, "error": "Internal error"}), 500

    @app.post("/api/wireless/chain")
    def wireless_chain():
        body = request.get_json(silent=True) or {}
        iface = str(body.get("interface", "")).strip() or None
        try:
            set_activity("Wireless assessment chain", iface or "auto")
            result = wifi_chain(iface)
            add_evidence(cfg, "wireless_chain", iface or "auto", "Bounded wireless discovery chain", json.dumps(result, ensure_ascii=False))
            log(cfg, "wireless_chain", iface or "auto", "OK", "fallback-enabled")
            clear_activity()
            return jsonify({"ok": True, **result})
        except Exception:
            clear_activity(); log(cfg, "wireless_chain", iface or "auto", "ERROR", "internal error")
            return jsonify({"ok": False, "error": "Internal error"}), 500

    @app.get("/api/wireless/attack-path")
    def wireless_attack_path():
        try:
            result = build_attack_paths(cfg)
            log(cfg, "wireless_attack_path", "wireless", "OK", result.get("status", "UNKNOWN"))
            return jsonify(result)
        except Exception as e:
            log(cfg, "wireless_attack_path", "wireless", "ERROR", str(e))
            return jsonify({"ok": False, "error": "Attack-path analysis failed"}), 500

    @app.post("/api/windows/fingerprint")
    def windows_fingerprint():
        body=request.get_json(silent=True) or {}
        target=str(body.get("target", "")).strip()
        try:
            set_activity("Windows fingerprint", target)
            result,recovery=retry_once(fingerprint,cfg,target)
            result["recovery"]=recovery
            add_evidence(cfg,"windows_fingerprint",target,"Windows/identity fingerprint",json.dumps(result,ensure_ascii=False))
            log(cfg,"windows_fingerprint",target,"OK",f"windows_indicator={result.get('windows_indicator')}")
            clear_activity()
            return jsonify({"ok":True,"result":result})
        except (ScopeError,WindowsFingerprintError) as e:
            clear_activity(); log(cfg,"windows_fingerprint",target,"BLOCKED",str(e)); return jsonify({"ok":False,"error":str(e)}),400
        except Exception as e:
            clear_activity(); log(cfg,"windows_fingerprint",target,"ERROR",str(e)); return jsonify({"ok":False,"error":"Windows fingerprint failed"}),500

    @app.post("/api/metasploit/search")
    def metasploit_search():
        body=request.get_json(silent=True) or {}
        try:
            return jsonify({"ok":True,"result":search_modules(cfg,str(body.get("query", "")),body.get("limit",20))})
        except MetasploitError as e:
            return jsonify({"ok":False,"error":str(e)}),400
        except Exception:
            return jsonify({"ok":False,"error":"Metasploit module search failed"}),500

    @app.post("/api/metasploit/check")
    def metasploit_check():
        body=request.get_json(silent=True) or {}
        target=str(body.get("target", "")).strip(); module=str(body.get("module", "")).strip(); rport=body.get("rport")
        try:
            set_activity("Metasploit CHECK", target)
            result=check_module(cfg,target,module,rport=rport)
            add_evidence(cfg,"metasploit_check",target,f"Metasploit CHECK {result.get('status')}",json.dumps(result,ensure_ascii=False))
            log(cfg,"metasploit_check",target,result.get("status","UNKNOWN"),module)
            clear_activity()
            return jsonify({"ok":True,"result":result})
        except (ScopeError,MetasploitError) as e:
            clear_activity(); log(cfg,"metasploit_check",target,"BLOCKED",str(e)); return jsonify({"ok":False,"error":str(e)}),400
        except Exception:
            clear_activity(); log(cfg,"metasploit_check",target,"ERROR",module); return jsonify({"ok":False,"error":"Metasploit check failed"}),500

    @app.post("/api/metasploit/run")
    def metasploit_run():
        body=request.get_json(silent=True) or {}
        target=str(body.get("target", "")).strip(); module=str(body.get("module", "")).strip(); lhost=str(body.get("lhost", "")).strip(); lport=body.get("lport",4444); rport=body.get("rport"); payload=str(body.get("payload", "windows/x64/meterpreter/reverse_tcp")).strip()
        try:
            if body.get("approval") is not True:
                return jsonify({"ok":False,"error":"RUN requires explicit approval."}),400
            assert_status = connect(cfg)
            row=assert_status.execute("SELECT id, created_at, data FROM evidence WHERE evidence_type='metasploit_check' AND target=? ORDER BY id DESC LIMIT 1",(target,)).fetchone()
            assert_status.close()
            if not row:
                return jsonify({"ok":False,"error":"Run requires a successful CHECK for this target/module first."}),400
            checked=json.loads(row["data"])
            if checked.get("module") != module or checked.get("target") != target or checked.get("status") != "VULNERABLE":
                return jsonify({"ok":False,"error":"RUN blocked: latest CHECK is not VULNERABLE for the selected target/module."}),400
            if time.time() - float(checked.get("checked_at",0)) > 900:
                return jsonify({"ok":False,"error":"RUN blocked: CHECK expired. Run CHECK again."}),400
            set_activity("Metasploit RUN", target)
            result=run_module(cfg,target,module,lhost,lport,payload,rport=rport if rport not in (None, "") else checked.get("rport"))
            add_evidence(cfg,"metasploit_run",target,"Metasploit execution result",json.dumps(result,ensure_ascii=False))
            log(cfg,"metasploit_run",target,"EXECUTED",module)
            clear_activity()
            return jsonify({"ok":True,"result":result})
        except (ScopeError,MetasploitError) as e:
            clear_activity(); log(cfg,"metasploit_run",target,"BLOCKED",str(e)); return jsonify({"ok":False,"error":str(e)}),400
        except Exception:
            clear_activity(); log(cfg,"metasploit_run",target,"ERROR",module); return jsonify({"ok":False,"error":"Metasploit execution failed"}),500

    @app.post("/api/metasploit/sessions/refresh")
    def metasploit_sessions_refresh():
        body=request.get_json(silent=True) or {}
        try:
            return jsonify({"ok": True, "result": refresh_session(str(body.get("id", "")))})
        except MetasploitError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception:
            return jsonify({"ok": False, "error": "Metasploit session refresh failed"}), 500

    @app.get("/api/metasploit/sessions")
    def metasploit_sessions():
        try:
            return jsonify({"ok": True, "sessions": list_sessions()})
        except Exception:
            return jsonify({"ok": False, "error": "Metasploit session status failed"}), 500

    @app.post("/api/metasploit/sessions/remote")
    def metasploit_remote_sessions():
        body=request.get_json(silent=True) or {}
        try:
            return jsonify({"ok": True, "result": remote_sessions(str(body.get("controller_id", "")))})
        except MetasploitError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception:
            return jsonify({"ok": False, "error": "Remote session enumeration failed"}), 500

    @app.post("/api/metasploit/sessions/interact")
    def metasploit_session_interact():
        body=request.get_json(silent=True) or {}
        controller=str(body.get("controller_id", "")).strip()
        remote_id=str(body.get("session_id", "")).strip()
        command=str(body.get("command", "")).strip()
        try:
            result=interact_session(controller,remote_id,command)
            log(cfg,"metasploit_session",result.get("session_id",""),"INTERACT",command[:200])
            add_evidence(cfg,"metasploit_session",result.get("session_id",""),"Metasploit session interaction",json.dumps(result,ensure_ascii=False))
            return jsonify({"ok": True, "result": result})
        except MetasploitError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception:
            return jsonify({"ok": False, "error": "Metasploit session interaction failed"}), 500


    @app.get("/api/v2/target/<target>/metasploit/candidates")
    def ux_target_metasploit_candidates(target):
        """Return only remotely checkable Metasploit exploit candidates matched to Nmap OS/service evidence."""
        target = target.strip()
        try:
            assert_target(cfg, target)
            services = list_service_inventory(cfg, target=target, limit=5000, latest_only=True)
            target_row = next((x for x in list_targets(cfg, 500) if str(x.get("address")) == target), None) or {}
            metadata = target_row.get("metadata") or {}
            osd = metadata.get("os_detection") or {}
            os_matches = osd.get("matches") or []
            os_classes = osd.get("classes") or []
            platform_hint = "unknown"
            os_label = "Unknown"
            os_accuracy = None
            raw_os = " ".join(str(x.get("name") or "") for x in os_matches).lower()
            raw_os += " " + " ".join(str(x.get(k) or "") for x in os_classes for k in ("vendor","osfamily","osgen")).lower()
            if any(x in raw_os for x in ("microsoft windows", "windows server", "windows 10", "windows 11", "windows 7", "windows xp")):
                platform_hint = "windows"
            elif any(x in raw_os for x in ("linux", "ubuntu", "debian", "red hat", "centos", "alpine", "fedora", "openwrt")):
                platform_hint = "linux"
            elif any(x in raw_os for x in ("freebsd", "openbsd", "netbsd")):
                platform_hint = "unix"
            if os_matches:
                os_label = str(os_matches[0].get("name") or "Unknown")
                try: os_accuracy = int(os_matches[0].get("accuracy"))
                except Exception: os_accuracy = None

            if not services:
                return jsonify({"ok": True, "target": target, "ready": False, "reason": "No persisted completed service inventory", "services": [], "candidates": [], "platform_hint": platform_hint, "os_label": os_label, "os_accuracy": os_accuracy})

            queries=[]; seen_queries=set()
            ranked=sorted(services, key=lambda r:(bool(r.get("version")),bool(r.get("product")),bool(r.get("service")),int(r.get("port") or 0)), reverse=True)
            for row in ranked[:16]:
                port=str(row.get("port") or "").strip(); service=str(row.get("service") or "").strip(); product=str(row.get("product") or "").strip()
                qs=[]
                if service and re.fullmatch(r"[A-Za-z0-9_.-]+", service): qs.append((f"type:exploit app:{service}","service_match"))
                if product:
                    token=re.sub(r"[^A-Za-z0-9_.-]", " ", product).strip()
                    if token: qs.append((f"type:exploit {token}","product_match"))
                if port: qs.append((f"type:exploit port:{port}","port_match"))
                for q,basis in qs:
                    if q not in seen_queries:
                        queries.append((q,row,basis)); seen_queries.add(q)
                if len(queries) >= 12: break

            modules={}; query_results=[]
            for q,row,basis in queries:
                result=search_modules(cfg,q,limit=20)
                query_results.append({"query":q,"basis":basis,"port":row.get("port"),"service":row.get("service"),"product":row.get("product"),"modules":result.get("modules",[])})
                for module in result.get("modules",[]):
                    # Exploitation view is intentionally remote + CHECK capable only.
                    if not module.startswith("exploit/"):
                        continue
                    if "/local/" in module or module.startswith("exploit/multi/local/"):
                        continue
                    try:
                        info=module_info(cfg,module)
                    except Exception:
                        continue
                    if not info.get("check_supported"):
                        continue
                    target_option = "RHOSTS" if "RHOSTS" in set(module_options(cfg,module).get("options",[])) else ("RHOST" if "RHOST" in set(module_options(cfg,module).get("options",[])) else None)
                    if not target_option:
                        continue
                    mplatforms=info.get("platforms") or []
                    if platform_hint != "unknown" and not _platform_compatible(platform_hint,mplatforms):
                        continue
                    item=modules.setdefault(module,{"module":module,"target":target,"type":"exploit","match_reasons":[],"matched_ports":[],"matched_services":[],"matched_products":[],"platform_hint":platform_hint,"platforms":mplatforms,"status":"CANDIDATE","requires_check":True,"requires_scope_and_approval":True,"target_option":target_option,"check_supported":True,"check_detail":info.get("check_raw") or "supported","rank":info.get("rank") or ""})
                    if basis not in item["match_reasons"]: item["match_reasons"].append(basis)
                    if row.get("port") and row.get("port") not in item["matched_ports"]: item["matched_ports"].append(row.get("port"))
                    if row.get("port") and "rport" not in item: item["rport"]=row.get("port")
                    if row.get("service") and row.get("service") not in item["matched_services"]: item["matched_services"].append(row.get("service"))
                    if row.get("product") and row.get("product") not in item["matched_products"]: item["matched_products"].append(row.get("product"))
            def score(item):
                r=item["match_reasons"]
                return (3 if "product_match" in r else 0)+(2 if "service_match" in r else 0)+(1 if "port_match" in r else 0)+(1 if "multi" in item.get("platforms",[]) else 0)
            candidates=sorted(modules.values(),key=lambda x:(-score(x),x["module"]))[:50]
            for item in candidates: item["evidence_match_score"]=score(item)
            result={"target":target,"ready":True,"platform_hint":platform_hint,"os_label":os_label,"os_accuracy":os_accuracy,"service_count":len(services),"services":services,"query_count":len(query_results),"queries":query_results,"candidates":candidates,"candidate_policy":"remote exploit modules with explicit CHECK support and OS compatibility; multi-platform remote exploits allowed","note":"Only remotely checkable exploit modules are shown. CHECK is required before RUN."}
            add_evidence(cfg,"metasploit_candidate_search",target,f"Automatic remote/checkable Metasploit search from {len(services)} persisted services",json.dumps(result,ensure_ascii=False))
            log(cfg,"metasploit_candidate_search",target,"OK",f"services={len(services)} candidates={len(candidates)} os={platform_hint}")
            return jsonify({"ok":True,**result})
        except (ScopeError, MetasploitError) as exc:
            return jsonify({"ok":False,"error":str(exc)}),400
        except Exception as exc:
            return jsonify({"ok":False,"error":f"Automatic Metasploit candidate search failed: {exc}"}),500

    @app.post("/api/metasploit/universal/match")
    def metasploit_universal_match():
        body = request.get_json(silent=True) or {}
        try:
            fp = TargetFingerprint(
                target=str(body.get("target", "")),
                platform=str(body.get("platform", "unknown")),
                architecture=str(body.get("architecture", "unknown")),
                services=list(body.get("services", []) or []),
                versions=dict(body.get("versions", {}) or {}),
                evidence=list(body.get("evidence", []) or []),
            )
            modules = [
                MetasploitModule(**m) for m in (body.get("modules", []) or [])
            ]
            matches = match_modules(fp, modules)
            plans = [build_validation_plan(fp, x) for x in matches]
            result = {"target": fp.target, "matches": matches, "validation_plans": plans}
            add_evidence(cfg, "metasploit_universal", fp.target or "unknown",
                         "Universal Metasploit capability matching",
                         json.dumps(result, ensure_ascii=False))
            return jsonify({"ok": True, "result": result})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.post("/api/post-session/advice")
    def post_session_advice():
        body = request.get_json(silent=True) or {}
        try:
            result = build_post_session_advice(body)
            target = result.get("target") or "session"
            add_evidence(cfg, "post_session_intelligence", target,
                         "Post-session recommendations",
                         json.dumps(result, ensure_ascii=False))
            return jsonify({"ok": True, "result": result})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.post("/api/session/probe")
    def session_probe():
        """Stage 2 Section 18-19: immediate post-session profiling.
        Probes OS, user, privilege, network interfaces via an existing
        Metasploit session. Evidence is stored; attack graph is updated.
        Never makes changes to the target — read-only commands only.
        """
        body = request.get_json(silent=True) or {}
        controller_id = str(body.get("controller_id", "")).strip()
        session_id = str(body.get("session_id", "")).strip()
        platform_hint = str(body.get("platform", "unknown")).strip().lower()
        if not controller_id or not session_id:
            return jsonify({"ok": False, "error": "controller_id and session_id are required"}), 400
        try:
            profile = si_probe_session(interact_session, controller_id, session_id, platform_hint)
            if profile.get("ok"):
                target = next((s.get("target") for s in list_sessions() if str(s.get("id")) == controller_id), controller_id)
                add_evidence(cfg, "post_session_probe", str(target or controller_id),
                             f"Session profile: os={profile.get('os')} priv={profile.get('privilege')} user={profile.get('user')}",
                             json.dumps(profile, ensure_ascii=False))
                log(cfg, "session_probe", f"{controller_id}:{session_id}", "OK",
                    f"os={profile.get('os')} priv={profile.get('privilege')}")
                # Trigger skill-based intelligence from session context
                try:
                    ctx = (f"Session profiled: OS={profile.get('os')} ({profile.get('os_confidence')}), "
                           f"user={profile.get('user')}, privilege={profile.get('privilege')}, "
                           f"interfaces={len(profile.get('interfaces', []))}")
                    llm.reason_with_skill(ctx, skill_ids=["session_intelligence", "privilege_context_intelligence"], _health=health_monitor)
                except Exception:
                    pass
            return jsonify({"ok": True, "profile": profile})
        except MetasploitError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"ok": False, "error": f"Session probe failed: {exc}"}), 500

    @app.post("/api/session/demo-account/create")
    def demo_account_create():
        """Stage 2 Sections 20-23: create a temporary ASEP demo account.
        Conditions enforced by session_intelligence.py (not skippable):
          - OS must be identified (linux/windows), not guessed
          - Privilege must be confirmed root/administrator
          - Username is always asep_demo_<timestamp>
        cleanup_state is always PENDING_OPERATOR_CONFIRMATION after creation.
        ASEP will NEVER automatically clean up this account.
        """
        body = request.get_json(silent=True) or {}
        controller_id = str(body.get("controller_id", "")).strip()
        session_id = str(body.get("session_id", "")).strip()
        platform = str(body.get("os", body.get("platform", ""))).strip().lower()
        privilege = str(body.get("privilege", "")).strip().lower()
        dry_run = bool(body.get("dry_run", False))
        if not controller_id or not session_id:
            return jsonify({"ok": False, "error": "controller_id and session_id are required"}), 400
        result = si_create_demo(interact_session, controller_id, session_id, platform, privilege, dry_run=dry_run)
        if result.get("ok") and not dry_run:
            target = next((s.get("target") for s in list_sessions() if str(s.get("id")) == controller_id), controller_id)
            account_id = db_create_demo(
                cfg, str(target or controller_id), controller_id, session_id,
                platform, result.get("os_confidence", ""), result["username"], privilege,
                result.get("create_output", ""), result.get("validation_output", ""),
            )
            result["account_id"] = account_id
            add_evidence(cfg, "demo_account_created", str(target or controller_id),
                         f"Demo account created: {result['username']} on {platform} (priv={privilege})",
                         json.dumps({**result, "account_id": account_id}, ensure_ascii=False))
            log(cfg, "demo_account", str(target or controller_id), "CREATED",
                f"user={result['username']} os={platform} priv={privilege}")
        elif not result.get("ok") and not dry_run:
            log(cfg, "demo_account", controller_id, "FAILED", result.get("reason", "unknown"))
        return jsonify({"ok": True, "result": result})

    @app.get("/api/session/demo-account/list")
    def demo_account_list():
        include_cleaned = request.args.get("include_cleaned", "false").lower() == "true"
        return jsonify({"ok": True, "accounts": list_demo_accounts(cfg, include_cleaned=include_cleaned)})

    @app.get("/api/session/demo-account/<int:account_id>/status")
    def demo_account_status(account_id):
        row = get_demo_account(cfg, account_id)
        if not row:
            return jsonify({"ok": False, "error": "Demo account not found"}), 404
        return jsonify({"ok": True, "account": row})

    @app.post("/api/session/demo-account/<int:account_id>/cleanup")
    def demo_account_cleanup(account_id):
        """Stage 2 Sections 24-25: EXPLICIT OPERATOR ACTION REQUIRED.
        This endpoint is the only path to cleanup — ASEP never auto-calls this.
        Body must include {"confirm": true} to prevent accidental invocation.
        LLM recommendations are NOT treated as operator confirmation.
        """
        body = request.get_json(silent=True) or {}
        if not body.get("confirm"):
            return jsonify({"ok": False,
                            "error": "Cleanup requires explicit operator confirmation. "
                            "Send {\"confirm\": true} to proceed. "
                            "This is NOT automatic — it requires a deliberate operator action."}), 400
        row = get_demo_account(cfg, account_id)
        if not row:
            return jsonify({"ok": False, "error": "Demo account not found"}), 404
        if row["cleanup_state"] == "CLEANUP_VERIFIED":
            return jsonify({"ok": True, "result": {"state": "CLEANUP_VERIFIED", "note": "Already cleaned up."}, "account": row})
        try:
            result = si_run_cleanup(interact_session, row["controller_id"], row["session_id"],
                                     row["os"], row["username"])
        except Exception as exc:
            result = {"ok": False, "reason": str(exc), "state": "CLEANUP_FAILED"}
        final_state = result.get("state", "CLEANUP_FAILED")
        record_demo_cleanup(cfg, account_id, final_state, json.dumps(result, ensure_ascii=False), cleanup_by="operator_explicit")
        log(cfg, "demo_account_cleanup", row["target"], final_state,
            f"user={row['username']} os={row['os']} result={result.get('ok')}")
        add_evidence(cfg, "demo_account_cleanup", row["target"],
                     f"Demo account cleanup {final_state}: {row['username']}",
                     json.dumps(result, ensure_ascii=False))
        return jsonify({"ok": True, "result": result, "final_state": final_state})

    @app.post("/api/target-path/passive-deep-dive")
    def target_path_passive_deep_dive():
        body = request.get_json(silent=True) or {}
        try:
            candidate = CandidateAsset(
                target=str(body.get("target", "")),
                scope_status=str(body.get("scope_status", "UNKNOWN")),
                evidence=list(body.get("evidence", []) or []),
                relationships=list(body.get("relationships", []) or []),
            )
            result = passive_deep_dive(candidate)
            add_evidence(cfg, "passive_deep_dive", candidate.target or "unknown",
                         "Passive target relationship analysis",
                         json.dumps(result, ensure_ascii=False))
            return jsonify({"ok": True, "result": result})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.post("/api/capabilities/recommend")
    def capabilities_recommend():
        body = request.get_json(silent=True) or {}
        obj = SecurityObjective(
            objective=str(body.get("objective", "")),
            evidence=list(body.get("evidence", []) or []),
            environment=list(body.get("environment", []) or []),
        )
        return jsonify({"ok": True, "capabilities": recommend_capabilities(obj)})

    @app.get("/api/skills")
    def list_reasoning_skills():
        return jsonify({"ok": True, "skills": skill_registry_inventory(cfg)})

    @app.post("/api/skills/reason")
    def skills_reason():
        body = request.get_json(silent=True) or {}
        context = str(body.get("context", "")).strip()
        skill_ids = body.get("skill_ids")
        if skill_ids is not None and not isinstance(skill_ids, list):
            return jsonify({"ok": False, "error": "skill_ids must be a list of skill id strings"}), 400
        if not context:
            return jsonify({"ok": False, "error": "context is required"}), 400
        result = llm.reason_with_skill(context, skill_ids=skill_ids)
        add_evidence(cfg, "skill_reasoning", ",".join(result.get("skill_ids") or []) or "auto",
                     f"mode={result.get('mode')}", json.dumps(result, ensure_ascii=False))
        return jsonify({"ok": True, **result})

    @app.post("/api/replan")
    def replan():
        body = request.get_json(silent=True) or {}
        state = PlanState(
            objective=str(body.get("objective", "")),
            evidence=list(body.get("evidence", []) or []),
            failed_actions=list(body.get("failed_actions", []) or []),
            blocked_paths=list(body.get("blocked_paths", []) or []),
            available_capabilities=list(body.get("available_capabilities", []) or []),
        )
        result = Replanner(llm=llm).replan(state)
        add_evidence(cfg, "adaptive_replan", state.objective or "environment",
                     "ASEP adaptive re-planning",
                     json.dumps(result, ensure_ascii=False))
        return jsonify({"ok": True, "result": result})

    @app.post("/api/self-modifying/preview")
    def self_modifying_preview():
        body = request.get_json(silent=True) or {}
        from .self_modifying import SelfModifier
        modifier = SelfModifier(cfg["root"], cfg.get("self_modify_max_file_bytes", 500000))
        try:
            return jsonify({"ok": True, "result": modifier.preview(body.get("changes", {}) or {})})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.post("/api/self-modifying/apply")
    def self_modifying_apply():
        body = request.get_json(silent=True) or {}
        try:
            result = repair_with_patch(
                cfg,
                body.get("changes", {}) or {},
                approved=bool(body.get("approval", False)),
                run_tests=bool(body.get("run_tests", True)),
            )
            status = "OK" if result.get("ok") else result.get("status", "BLOCKED")
            log(cfg, "self_modifying", "ASEP", status, result.get("error", "checkpoint/test/rollback pipeline"))
            return jsonify(result), (200 if result.get("ok") else 400)
        except Exception as e:
            log(cfg, "self_modifying", "ASEP", "ERROR", str(e))
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/self-heal/health")
    def self_heal_health():
        return jsonify({"ok": True, "result": self_health(cfg)})

    @app.get("/api/tools")
    def tools_inventory():
        return jsonify({"ok": True, "tools": tool_inventory()})

    @app.post("/api/tools/plan")
    def tools_plan():
        body=request.get_json(silent=True) or {}
        target=str(body.get("target","")).strip()
        try:
            items=list_evidence(cfg)[:80]
            target_evidence=[x for x in items if x.get("target")==target]
            return jsonify({"ok":True, **plan_for_target(cfg,target,target_evidence)})
        except (ScopeError,ToolError) as e:
            return jsonify({"ok":False,"error":str(e)}),400

    @app.post("/api/tools/run")
    def tools_run():
        body=request.get_json(silent=True) or {}
        tool=str(body.get("tool","")).strip(); profile=str(body.get("profile","")).strip(); target=str(body.get("target","")).strip() or None; interface=str(body.get("interface","")).strip() or None
        try:
            set_activity(f"Tool: {tool}", target or profile)
            result=run_profile(cfg,tool,profile,target,interface,cfg.get("tool_timeout",300))
            add_evidence(cfg,"tool_execution",target or interface or tool,f"{tool}/{profile} completed",json.dumps(result,ensure_ascii=False))
            log(cfg,"tool_execution",target or interface or tool,"OK",f"{tool}/{profile}")
            clear_activity()
            return jsonify({"ok":True,"result":result})
        except (ScopeError,ToolError) as e:
            clear_activity(); log(cfg,"tool_execution",target or interface or tool,"BLOCKED",str(e)); return jsonify({"ok":False,"error":str(e)}),400
        except Exception as e:
            clear_activity(); log(cfg,"tool_execution",target or interface or tool,"ERROR",str(e)); return jsonify({"ok":False,"error":"Tool execution failed"}),500

    @app.post("/api/tools/execute-chain")
    def tools_execute_chain():
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        depth = str(body.get("depth", "standard")).strip().lower()
        if depth not in {"standard", "deep"}:
            return jsonify({"ok": False, "error": "depth must be standard or deep"}), 400
        try:
            set_activity("ASEP real Kali evidence chain", target)
            result = run_chain(cfg, target, depth)
            add_evidence(
                cfg,
                "assessment_chain",
                target,
                json.dumps({"depth": depth, "executed": len(result.get("executed", [])), "skipped": len(result.get("skipped", []))}),
                json.dumps(result, ensure_ascii=False),
            )
            log(cfg, "assessment_chain", target, "OK", f"depth={depth};executed={len(result.get('executed', []))}")
            clear_activity()
            return jsonify(result)
        except (ScopeError, AssessmentError, ToolError) as e:
            clear_activity(); log(cfg, "assessment_chain", target, "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:
            clear_activity(); log(cfg, "assessment_chain", target, "ERROR", str(e))
            return jsonify({"ok": False, "error": "Assessment chain failed"}), 500

    @app.post("/api/research/nvd")
    def research_nvd():
        if not cfg.get("internet_research_enabled"):
            return jsonify({"ok":False,"error":"Internet research disabled"}),400
        body=request.get_json(silent=True) or {}; query=str(body.get("query","")).strip()
        try:
            result=nvd_cves(query,body.get("limit",5)); add_evidence(cfg,"internet_research",query,"NVD research result",json.dumps(result,ensure_ascii=False)); log(cfg,"internet_research",query,"OK","NVD"); return jsonify(result)
        except Exception as e:
            log(cfg,"internet_research",query,"ERROR",str(e)); return jsonify({"ok":False,"error":"Internet research failed"}),500

    @app.get("/api/target/<target>")
    def target_profile(target):
        """Build a scoped target profile for an IP selected from the Network Map.

        This endpoint performs bounded discovery/validation only. It does not
        launch exploitation or credential attacks.
        """
        target = target.strip()
        try:
            # Reuse the existing Nmap scope enforcement.
            set_activity("Target deep discovery", target)
            result = run_nmap(cfg, target, "service_full")
            add_evidence(
                cfg,
                "target_profile",
                target,
                json.dumps({"hosts": len(result.get("hosts", [])), "services": sum(len(h.get("ports", [])) for h in result.get("hosts", []))}),
                json.dumps(result, ensure_ascii=False),
            )
            log(cfg, "target_profile", target, "OK", "service_full")
            clear_activity()
            host = next((h for h in result.get("hosts", []) if any(target == a for a in h.get("addresses", []))), None)
            if host is None and result.get("hosts"):
                host = result["hosts"][0]
            return jsonify({"ok": True, "target": target, "host": host, "profile": "service_full"})
        except (ScopeError, NmapError) as e:
            clear_activity(); log(cfg, "target_profile", target, "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:
            clear_activity(); log(cfg, "target_profile", target, "ERROR", str(e))
            return jsonify({"ok": False, "error": "Target profiling failed"}), 500

    @app.post("/api/target/action")
    def target_action():
        """Run bounded, evidence-producing actions for a selected in-scope target."""
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        action = str(body.get("action", "")).strip().lower()
        allowed = {"deep_recon", "validate_services", "analyze_attack_path"}
        if action not in allowed:
            return jsonify({"ok": False, "error": "Unsupported target action"}), 400
        try:
            if action in {"deep_recon", "validate_services"}:
                set_activity("Target validation", target)
                profile = "service_full" if action == "deep_recon" else "service"
                result = run_nmap(cfg, target, profile)
                host = next((h for h in result.get("hosts", []) if target in (h.get("addresses") or [])), result.get("hosts", [{}])[0] if result.get("hosts") else {})
                ident = enrich_identity(target, host.get("mac"), (host.get("hostnames") or [""])[0], host.get("vendor", ""))
                inferred = infer_asset_type(ident.get("vendor"), ident.get("hostname"), "unknown", host.get("ports", []), target)
                existing = next((x for x in list_targets(cfg, 500) if str(x.get("address")) == target), None)
                upsert_target(cfg, {
                    "address": target, "name": ident.get("hostname") or (existing or {}).get("name") or target,
                    "role": inferred["type"], "state": host.get("state", "up"),
                    "scope_status": (existing or {}).get("scope_status", "IN-SCOPE"), "mac": ident.get("mac_normalized"),
                    "vendor": ident.get("vendor"), "interface": (existing or {}).get("interface"),
                    "source": (existing or {}).get("source", "target-validation"),
                    "metadata": {**((existing or {}).get("metadata") or {}), "hostname": ident.get("hostname", ""), "vendor": ident.get("vendor", ""), "identity": ident, "ports": host.get("ports", [])}
                })
                if action == "validate_services":
                    observed = []
                    for p in host.get("ports", []) or []:
                        state = str(p.get("state") or "").lower()
                        if state in {"open", "open|filtered"} or p.get("service"):
                            observed.append({
                                "port": p.get("port", ""),
                                "protocol": p.get("protocol", ""),
                                "state": p.get("state", ""),
                                "service": p.get("service", ""),
                                "product": p.get("product", ""),
                                "version": p.get("version", ""),
                                "detection": "Nmap -sV",
                            })
                    service_payload = {
                        "target": target,
                        "profile": profile,
                        "scanner": "nmap",
                        "method": "-sV --top-ports 100",
                        "host_state": host.get("state", "unknown"),
                        "ports": observed,
                        "port_count": len(observed),
                    }
                    add_evidence(cfg, "service_scan", target, json.dumps({"services": len(observed), "profile": profile}), json.dumps(service_payload, ensure_ascii=False))
                else:
                    add_evidence(cfg, "target_action", target, json.dumps({"action": action, "hosts": len(result.get("hosts", []))}), json.dumps(result, ensure_ascii=False))
                log(cfg, "target_action", target, "OK", action)
                clear_activity()
                return jsonify({"ok": True, "action": action, "target": target, "result": result})
            # Correlation only; no exploitation.
            set_activity("Attack-path correlation", target)
            paths = build_attack_paths(cfg)
            log(cfg, "target_action", target, "OK", "analyze_attack_path")
            clear_activity()
            return jsonify({"ok": True, "action": action, "target": target, "result": paths})
        except (ScopeError, NmapError) as e:
            clear_activity(); log(cfg, "target_action", target, "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:
            clear_activity(); log(cfg, "target_action", target, "ERROR", str(e))
            return jsonify({"ok": False, "error": "Target action failed"}), 500

    @app.get("/api/skills")
    def skills():
        return jsonify({"ok": True, "skills": skill_inventory()})

    @app.post("/api/adaptive/analyze")
    def adaptive_analyze():
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        observations = body.get("observations", [])
        edges = body.get("edges", [])
        nodes = body.get("nodes", [])
        decoy = assess_deception(target, body.get("fingerprint") or {}, observations)
        result = {
            "hypotheses": build_hypotheses(target, observations),
            "alternative_paths": alternative_paths(nodes, edges, body.get("start")),
            "correlation": correlate(target, observations, decoy),
        }
        add_evidence(cfg, "adaptive_reasoning", target or "environment", "ASEP adaptive reasoning", json.dumps(result, ensure_ascii=False))
        log(cfg, "adaptive_reasoning", target or "environment", "OK", "hypotheses/paths/deception")
        return jsonify({"ok": True, "result": result})

    @app.post("/api/deception/assess")
    def deception_assess():
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        result = assess_deception(target, body.get("fingerprint") or {}, body.get("observations", []))
        add_evidence(cfg, "deception_assessment", target or "environment", "ASEP deception assessment", json.dumps(result, ensure_ascii=False))
        log(cfg, "deception_assessment", target or "environment", "OK", result.get("status", "UNKNOWN"))
        return jsonify({"ok": True, "result": result})

    @app.post("/api/settings/llm-mode")
    def set_llm_mode():
        body = request.get_json(silent=True) or {}
        mode = str(body.get("mode", "")).strip().lower()
        valid_modes = {"auto", "cloud", "local", "claude_code"}
        if mode not in valid_modes:
            return jsonify({"ok": False, "error": f"Invalid mode. Must be one of: {', '.join(sorted(valid_modes))}"}), 400
        cfg["llm_mode"] = mode  # cfg is the same dict LLMRouter holds a reference to -- takes effect immediately
        try:
            persist_env_var(cfg["root"], "ASEP_LLM_MODE", mode)
            persisted = True
        except OSError as exc:
            persisted = False
            log(cfg, "settings", "llm_mode", "WARNING", f"In-memory switch OK but could not persist to .env: {exc}")
        log(cfg, "settings", "llm_mode", "OK", f"Switched to {mode}")
        return jsonify({"ok": True, "requested_mode": mode, "active_mode": llm.mode(), "persisted_to_env": persisted})

    @app.get("/api/provider-health")
    def provider_health_api():
        return jsonify({"ok": True, **health_monitor.snapshot()})

    @app.get("/api/intelligence/status")
    def intelligence_status():
        snap = health_monitor.snapshot()
        local = {"enabled": bool(cfg.get("local_enabled")), "model": cfg.get("local_model"), "ollama_url": cfg.get("ollama_url")}
        cloud = {"configured": bool(cfg.get("openai_api_key")), "model": cfg.get("cloud_model")}
        claude_binary_path = shutil.which(cfg.get("claude_code_binary") or "claude")
        claude_code = {
            "enabled": bool(cfg.get("claude_code_enabled")),
            "installed": bool(claude_binary_path),
            "binary_path": claude_binary_path,
        }
        return jsonify({
            "ok": True,
            "mode": llm.mode(),
            "requested_mode": cfg.get("llm_mode", "auto"),
            "local": local,
            "cloud": cloud,
            "claude_code": claude_code,
            "internet": snap.get("internet", "CHECKING"),
            "provider_health": {k: snap[k] for k in ("local_llm", "cloud", "claude_code", "active_provider", "current_task", "last_check_age_s") if k in snap},
            "context_limit_chars": cfg.get("intelligence_context_chars", 30000),
        })

    @app.get("/api/v2/intelligence/summary")
    def ux_intelligence_summary_api():
        with network_map_lock:
            nm = network_map.get("data") or {}
        try:
            ap = build_attack_paths(cfg)
        except Exception:
            ap = {"paths": [], "findings": []}
        return jsonify(ux_intelligence_summary(cfg, nm, ap))

    @app.post("/api/intelligence/analyze")
    def intelligence_analyze():
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip() or None
        use_cloud = bool(body.get("use_cloud", True))
        use_local = bool(body.get("use_local", True))
        try:
            set_activity("ASEP Intelligence", target or "current environment")
            with network_map_lock:
                nm = network_map.get("data") or {}
            items = list_evidence(cfg)
            # Keep the intelligence context bounded for the old X230. Most recent evidence first.
            items = items[:80]
            wireless_items = [x for x in items if x.get("evidence_type", "").startswith("wireless")]
            wireless = {"recent_evidence": wireless_items[:20]}
            try:
                ap = build_attack_paths(cfg)
            except Exception as exc:
                ap = {"status": "unavailable", "error": str(exc)}
            context = intelligence.build_context(
                network_map=nm,
                evidence=items,
                wireless=wireless,
                attack_path=ap,
                target=target,
            )
            result = intelligence.analyze(context, use_cloud=use_cloud, use_local=use_local)
            add_evidence(cfg, "intelligence", target or "environment", "ASEP Intelligence Engine analysis", json.dumps(result, ensure_ascii=False))
            log(cfg, "intelligence_analysis", target or "environment", "OK", result.get("mode", "unknown"))
            clear_activity()
            return jsonify(result)
        except Exception as e:
            clear_activity()
            log(cfg, "intelligence_analysis", target or "environment", "ERROR", str(e))
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/evidence")
    def evidence():
        return jsonify(list_evidence(cfg))

    @app.get("/api/evidence/<int:evidence_id>")
    def evidence_detail(evidence_id):
        item = get_evidence(cfg, evidence_id)
        if not item:
            return jsonify({"error": "Evidence not found"}), 404
        return jsonify(item)

    @app.post("/api/scan")
    def scan():
        body = request.get_json(silent=True) or {}
        target = str(body.get("target", "")).strip()
        profile = str(body.get("profile", "quick")).strip()

        try:
            set_activity("Nmap scan", target)
            result = run_nmap(cfg, target, profile)

            summary = json.dumps(
                {
                    "hosts": len(result["hosts"]),
                    "services": sum(len(h["ports"]) for h in result["hosts"]),
                    "profile": profile,
                }
            )

            add_evidence(
                cfg,
                "nmap",
                target,
                summary,
                json.dumps(result, ensure_ascii=False),
            )

            log(cfg, "nmap_scan", target, "OK", profile)
            clear_activity()

            return jsonify({
                "ok": True,
                "target": target,
                "profile": profile,
                "hosts": result["hosts"],
            })

        except (ScopeError, NmapError) as e:
            clear_activity()
            log(cfg, "nmap_scan", target, "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400

        except Exception as e:
            clear_activity()
            log(cfg, "nmap_scan", target, "ERROR", str(e))
            return jsonify({"ok": False, "error": "Internal error"}), 500

    @app.get("/api/privilege")
    def privilege_status():
        return jsonify({
            **current_user(),
            "root_approval_required": bool(cfg.get("root_approval_required", True)),
        })

    @app.post("/api/sudo")
    def sudo_shell():
        body = request.get_json(silent=True) or {}
        command = str(body.get("command", "")).strip()
        approved = bool(body.get("approved", False))

        try:
            result = run_with_sudo(cfg, command, approved=approved)
            log(cfg, "root_shell", "localhost", "OK", command)
            return jsonify({"ok": True, **result})
        except PrivilegeError as e:
            log(cfg, "root_shell", "localhost", "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:
            log(cfg, "root_shell", "localhost", "ERROR", str(e))
            return jsonify({"ok": False, "error": "Internal error"}), 500

    @app.post("/api/shell")
    def shell():
        body = request.get_json(silent=True) or {}
        command = str(body.get("command", "")).strip()

        try:
            set_activity("Local shell", "localhost")
            result = run_shell(cfg, command)
            log(cfg, "local_shell", "localhost", "OK", command)
            clear_activity()
            return jsonify({"ok": True, **result})
        except ShellError as e:
            clear_activity()
            log(cfg, "local_shell", "localhost", "BLOCKED", str(e))
            return jsonify({"ok": False, "error": str(e)}), 400
        except Exception as e:
            clear_activity()
            log(cfg, "local_shell", "localhost", "ERROR", str(e))
            return jsonify({"ok": False, "error": "Internal error"}), 500

    @app.post("/api/analyze")
    def analyze():
        body = request.get_json(silent=True) or {}
        evidence_id = body.get("evidence_id")

        if not evidence_id:
            return jsonify({"error": "evidence_id required"}), 400

        item = get_evidence(cfg, int(evidence_id))
        if not item:
            return jsonify({"error": "Evidence not found"}), 404

        result = llm.ask(
            "Analyze this Nmap evidence. Do not claim a vulnerability is confirmed "
            "without sufficient evidence.\n\n" + item["data"]
        )

        log(cfg, "llm_analysis", item["target"], "OK", result["mode"])

        return jsonify(result)


    @app.get("/api/v2/target/<target>/services")
    def ux_target_services(target):
        services = list_service_inventory(cfg, target=target.strip(), limit=5000, latest_only=True)
        scan = latest_service_scan(cfg, target.strip())
        return jsonify({"ok": True, "target": target.strip(), "scan": scan, "services": services, "service_count": len(services)})

    @app.get("/api/v2/services/inventory")
    def ux_service_inventory():
        services = list_service_inventory(cfg, limit=10000, latest_only=True)
        return jsonify({"ok": True, "services": services, "service_count": len(services)})

    @app.get("/api/v2/services/nmap.xml")
    def ux_all_services_nmap_xml():
        # Merge the latest completed per-target Nmap XML documents into one
        # tool-consumable Nmap XML document. This is directly suitable for
        # downstream inventory consumers and Metasploit db_import.
        import xml.etree.ElementTree as ET
        root = ET.Element("nmaprun", {"scanner": "nmap", "args": "ASEP persisted service inventory", "version": "ASEP"})
        host_count = 0
        targets = sorted({r.get("target") for r in list_service_inventory(cfg, limit=10000, latest_only=True) if r.get("target")})
        for target in targets:
            xml = latest_service_scan_xml(cfg, target)
            if not xml:
                continue
            try:
                src = ET.fromstring(xml)
                for host in src.findall("host"):
                    root.append(host)
                    host_count += 1
            except ET.ParseError:
                continue
        if host_count == 0:
            return jsonify({"error": "No persisted completed service scans"}), 404
        payload = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        return Response(payload, mimetype="application/xml", headers={"Content-Disposition": 'attachment; filename="asep-service-inventory.xml"'})

    @app.get("/api/v2/target/<target>/services/nmap.xml")
    def ux_target_services_nmap_xml(target):
        xml = latest_service_scan_xml(cfg, target.strip())
        if not xml:
            return jsonify({"error": "No persisted Nmap service scan for target"}), 404
        return Response(xml, mimetype="application/xml", headers={"Content-Disposition": f'attachment; filename="asep-{target.strip().replace(":", "_")}-services.xml"'})

    @app.get("/api/v2/target/<target>")
    def ux_target_detail(target):
        """Read-only target view for dashboard/graph interactions. Never starts a scan."""
        target = target.strip()
        item = next((x for x in list_targets(cfg, 500) if str(x.get("address")) == target), None)
        evidence_rows = [x for x in list_evidence(cfg, 200, include_data=True) if str(x.get("target")) == target]
        latest_scan = None
        for ev in evidence_rows:
            if ev.get("evidence_type") in {"service_scan", "target_action", "target_profile", "nmap", "network_map"}:
                try:
                    payload = json.loads(ev.get("data") or "{}")
                except Exception:
                    payload = {}
                latest_scan = {"id": ev.get("id"), "created_at": ev.get("created_at"), "type": ev.get("evidence_type"), "payload": payload}
                break
        md = (item or {}).get("metadata") or {}
        identity = enrich_identity(target, (item or {}).get("mac") or md.get("mac"), (item or {}).get("name") or md.get("hostname"), (item or {}).get("vendor") or md.get("vendor"))
        ports = md.get("ports", []) if isinstance(md, dict) else []
        if latest_scan:
            payload = latest_scan.get("payload", {}) or {}
            host_candidates = payload.get("result", {}).get("hosts", []) or payload.get("hosts", []) or []
            host = next((h for h in host_candidates if target in (h.get("addresses") or [])), host_candidates[0] if host_candidates else None)
            if host:
                ports = host.get("ports", ports) or ports
                identity = enrich_identity(target, host.get("mac") or identity.get("mac_normalized"), (host.get("hostnames") or [identity.get("hostname")])[0] if (host.get("hostnames") or [identity.get("hostname")])[0] else "", host.get("vendor") or identity.get("vendor"))
            elif latest_scan.get("type") == "service_scan":
                ports = payload.get("ports", ports) or ports
        persisted_services = list_service_inventory(cfg, target=target, limit=5000, latest_only=True)
        if persisted_services:
            ports = [{
                "port": str(p.get("port")), "protocol": p.get("protocol"), "state": p.get("state"),
                "service": p.get("service"), "product": p.get("product"), "version": p.get("version"),
                "extrainfo": p.get("extrainfo"), "tunnel": p.get("tunnel"), "method": p.get("method"),
                "confidence": p.get("confidence"), "cpe": p.get("cpe"), "reason": p.get("reason"),
                "detection": "Nmap deep_full / persisted", "scan_id": p.get("scan_id"),
            } for p in persisted_services]
        observed_ports = [p for p in ports if str(p.get("state", "")).lower() in {"open", "open|filtered"} or p.get("service")]
        inferred = infer_asset_type(identity.get("vendor"), identity.get("hostname"), (item or {}).get("role", "unknown"), observed_ports, target)
        ctx = local_context()
        role_info = infer_network_role(target, identity.get("hostname"), identity.get("vendor"), observed_ports, ctx.get("gateway"), target in {x.get("ip") for x in ctx.get("local_ips", [])})
        topology = {"gateway": ctx.get("gateway"), "interface": (item or {}).get("interface") or ctx.get("gateway_iface"), "role_basis": role_info["basis"], "role_confidence": role_info["confidence"]}
        return jsonify({"ok": True, "target": {
            "address": target, "hostname": identity.get("hostname") or "Hostname not resolved",
            "mac": identity.get("mac_normalized") or "MAC unavailable", "vendor": identity.get("vendor") or "Manufacturer not resolved",
            "asset_type": inferred["type"], "asset_confidence": inferred["confidence"], "asset_basis": inferred["basis"],
            "role": role_info["role"], "role_confidence": role_info["confidence"], "role_basis": role_info["basis"], "state": (item or {}).get("state", "unknown"),
            "scope_status": (item or {}).get("scope_status", "UNKNOWN"), "interface": (item or {}).get("interface", ""),
            "first_seen": (item or {}).get("first_seen"), "last_seen": (item or {}).get("last_seen"),
            "services": observed_ports, "service_count": len(observed_ports), "evidence_count": len(evidence_rows),
            "metasploit_ready": bool(persisted_services and any((p.get("service") or p.get("product") or p.get("version")) for p in persisted_services)),
            "latest_scan": latest_scan, "evidence": evidence_rows[:20],
            "identity_sources": identity.get("vendor_sources", []), "topology": topology,
        }})

    # ------------------------------------------------------------------
    # ASEP v2.9 UX aggregation API. These endpoints are read-only views
    # over existing v2.8.2 evidence/engine state; they do not replace or
    # bypass the existing execution/scope controls.
    # ------------------------------------------------------------------
    @app.get("/api/v2/dashboard")
    def ux_dashboard_api():
        _ensure_auto_awareness()
        with network_map_lock:
            nm = network_map.get("data") or {}
        try:
            ap = build_attack_paths(cfg)
        except Exception:
            ap = {"status": "UNAVAILABLE", "nodes": [], "edges": [], "paths": [], "findings": []}
        try:
            sessions = list_sessions()
        except Exception:
            sessions = []
        data = ux_dashboard(cfg, nm, ap, sessions, monitor)
        try:
            data["environment"] = environment_candidates(cfg)
        except Exception:
            data["environment"] = {"ok": False, "candidates": [], "primary": None}
        with awareness_lock:
            data["awareness"] = {"last_started": awareness.get("last_started"), "last_network": awareness.get("last_network"), "service_queue": len(awareness.get("service_queue", [])), "service_running": bool(awareness.get("service_running"))}
        with deep_scan_lock:
            data["deep_scan"] = dict(deep_scan)
        return jsonify(data)

    @app.get("/api/v2/targets")
    def ux_targets_api():
        with network_map_lock:
            nm = network_map.get("data") or {}
        return jsonify({"ok": True, "targets": [x.__dict__ for x in ux_targets(cfg, nm)], "inventory": list_targets(cfg, 500)})

    @app.get("/api/v2/environment")
    def ux_environment_api():
        return jsonify(environment_candidates(cfg))

    @app.get("/api/v2/targets/<address>/exploit-candidates")
    def ux_target_exploit_candidates_api(address):
        with network_map_lock:
            nm = network_map.get("data") or {}
        target = next((t for t in ux_targets(cfg, nm) if t.address == address), None)
        if not target:
            return jsonify({"ok": False, "error": f"Target {address} not found in inventory."}), 404
        result = find_target_candidates(cfg, target.ports or [])
        add_evidence(cfg, "exploit_candidates", address,
                      f"{result['services_checked']} service(s) checked", json.dumps(result, ensure_ascii=False))
        return jsonify(result)

    @app.get("/api/v2/discovery-history")
    def ux_discovery_history_api():
        return jsonify({"ok": True, "runs": list_discovery_runs(cfg, 50)})

    @app.get("/api/v2/evidence")
    def ux_evidence_api():
        return jsonify({"ok": True, "evidence": [x.__dict__ for x in ux_evidence(cfg, 150)]})

    @app.get("/api/v2/findings")
    def ux_findings_api():
        try:
            ap = build_attack_paths(cfg)
        except Exception:
            ap = {}
        findings = ux_findings(cfg, ap)
        return jsonify({"ok": True, "findings": [x.__dict__ for x in findings]})

    @app.get("/api/v2/attack-paths")
    def ux_attack_paths_api():
        try:
            result = build_attack_paths(cfg)
        except Exception as exc:
            result = {"status": "UNAVAILABLE", "error": str(exc), "nodes": [], "edges": [], "paths": [], "findings": []}
        return jsonify({"ok": True, "result": result})

    @app.get("/api/v2/recommendations")
    def ux_recommendations_api():
        try:
            ap = build_attack_paths(cfg)
        except Exception:
            ap = {}
        findings = ux_findings(cfg, ap)
        with network_map_lock:
            nm = network_map.get("data") or {}
        targets = ux_targets(cfg, nm)
        recs = ux_recommendations(cfg, findings, targets)
        return jsonify({"ok": True, "recommendations": [x.__dict__ for x in recs]})

    @app.get("/api/v2/sessions")
    def ux_sessions_api():
        try:
            return jsonify({"ok": True, "sessions": list_sessions()})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc), "sessions": []}), 500

    @app.get("/api/v2/activity")
    def ux_activity_api():
        return jsonify({"ok": True, "activity": ux_activity(cfg, 40)})

    @app.get("/api/v2/capabilities")
    def ux_capabilities_api():
        return jsonify({"ok": True, "families": [
            {"id":"recon","title":"Recon & OSINT","description":"Passive discovery, attack surface and internet research."},
            {"id":"network","title":"Network Security","description":"Network services, topology, protocols and validation."},
            {"id":"web-api","title":"Web & API","description":"Authentication, authorization, business logic and API attack surface."},
            {"id":"identity","title":"Identity & Directory","description":"Identity, directory and trust-boundary analysis."},
            {"id":"cloud","title":"Cloud Security","description":"Cloud identity, storage, workload and trust analysis."},
            {"id":"wireless","title":"Wireless Security","description":"Wi-Fi posture, wireless discovery and evidence-backed paths."},
            {"id":"linux","title":"Linux & Unix","description":"Linux service, privilege and host security assessment."},
            {"id":"windows","title":"Windows","description":"Windows service, identity and host validation."},
            {"id":"research","title":"Vulnerability Research","description":"CVE research, reverse engineering and controlled validation."},
            {"id":"execution","title":"Exploitation & Sessions","description":"Controlled exploitation, session management and post-session intelligence."},
            {"id":"evidence","title":"Evidence & Findings","description":"Evidence provenance, findings, timelines and reporting."},
            {"id":"platform","title":"Platform","description":"Skills, self-healing, self-modifying and runtime settings."},
        ]})

    return app
