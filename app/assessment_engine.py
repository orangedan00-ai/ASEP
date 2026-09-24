import json
import shutil
import time
from .nmap_executor import run_nmap, NmapError
from .scope import assert_target, ScopeError
from .tool_orchestrator import run_profile, ToolError
from .windows_fingerprint import fingerprint, WindowsFingerprintError


class AssessmentError(Exception):
    pass


def _has_port(host, ports):
    wanted = {str(p) for p in ports}
    return any(str(x.get("port")) in wanted and x.get("state") == "open" for x in host.get("ports", []))


def _host_for_target(result, target):
    for host in result.get("hosts", []):
        if target in host.get("addresses", []):
            return host
    return result.get("hosts", [None])[0]


def _run_optional(cfg, tool, profile, target, executed, skipped):
    meta = None
    try:
        from .tool_registry import get_tool
        meta = get_tool(tool)
    except Exception:
        skipped.append({"tool": tool, "profile": profile, "reason": "not registered"})
        return
    if not shutil.which(meta["binary"]):
        skipped.append({"tool": tool, "profile": profile, "reason": "tool not installed"})
        return
    try:
        r = run_profile(cfg, tool, profile, target=target, timeout=cfg.get("tool_timeout", 300))
        executed.append(r)
    except Exception as exc:
        skipped.append({"tool": tool, "profile": profile, "reason": str(exc)})


def run_chain(cfg, target, depth="standard"):
    """Run a bounded real-Kali evidence chain against one in-scope target.

    The engine never performs credential attacks, persistence, DoS, destructive
    actions, or arbitrary exploit execution. Each step produces evidence and
    later steps are selected from observed services.
    """
    assert_target(cfg, target)
    started = time.time()
    executed = []
    skipped = []

    try:
        nmap_profile = "service_full" if depth == "deep" else "service"
        nmap = run_nmap(cfg, target, nmap_profile)
    except (ScopeError, NmapError) as exc:
        raise AssessmentError(str(exc)) from exc

    host = _host_for_target(nmap, target) or {}
    ports = host.get("ports", [])
    windows = None
    # Windows fingerprinting is evidence-only and precedes any exploitation workflow.
    if _has_port(host, {135,139,389,445,636,3268,3269,3389,5985,5986}):
        try:
            windows = fingerprint(cfg, target)
        except Exception as exc:
            skipped.append({"tool":"nmap","profile":"windows_fingerprint","reason":str(exc)})

    # Web evidence: only when a web service is actually observed.
    if _has_port(host, {80, 8080, 8000, 8008, 8081}):
        _run_optional(cfg, "httpx", "http", target, executed, skipped)
        _run_optional(cfg, "whatweb", "web", target, executed, skipped)
        _run_optional(cfg, "nikto", "nikto", target, executed, skipped)
        if depth == "deep":
            _run_optional(cfg, "nuclei", "vuln", target, executed, skipped)
    if _has_port(host, {443, 8443, 9443}):
        _run_optional(cfg, "httpx", "http", target, executed, skipped)
        _run_optional(cfg, "whatweb", "web", target, executed, skipped)
        _run_optional(cfg, "sslscan", "tls", target, executed, skipped)
        if depth == "deep":
            _run_optional(cfg, "nuclei", "vuln", target, executed, skipped)

    # SMB/LDAP evidence: enumeration only; no credential spraying or auth attacks.
    if _has_port(host, {445, 139}):
        _run_optional(cfg, "netexec", "smb", target, executed, skipped)
        _run_optional(cfg, "enum4linux", "smb", target, executed, skipped)
    if _has_port(host, {389, 636, 3268, 3269}):
        _run_optional(cfg, "netexec", "ldap", target, executed, skipped)

    return {
        "ok": True,
        "target": target,
        "depth": depth,
        "started_at": started,
        "elapsed_sec": round(time.time() - started, 2),
        "nmap": nmap,
        "windows_fingerprint": windows,
        "observed_ports": ports,
        "executed": executed,
        "skipped": skipped,
        "chain": [
            "DISCOVER",
            "ANALYZE",
            "SELECT_TOOLS",
            "EXECUTE",
            "COLLECT_EVIDENCE",
            "CORRELATE",
        ],
    }
