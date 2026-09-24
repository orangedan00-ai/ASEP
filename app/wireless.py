import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional


class WirelessError(Exception):
    pass


def _run(cmd: List[str], timeout: int = 30) -> str:
    if not shutil.which(cmd[0]):
        raise WirelessError(f"Tool not installed: {cmd[0]}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise WirelessError(f"Command timed out: {' '.join(cmd)}")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip()
        raise WirelessError(msg or f"Command failed: {' '.join(cmd)}")
    return p.stdout


def interfaces() -> Dict:
    out = {}
    try:
        text = _run(["iw", "dev"])
        for line in text.splitlines():
            m = re.match(r"\s*Interface\s+(\S+)", line)
            if m:
                out[m.group(1)] = {"name": m.group(1), "source": "iw"}
    except WirelessError:
        pass
    if not out:
        try:
            text = _run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"])
            for line in text.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "wifi":
                    out[parts[0]] = {"name": parts[0], "type": "wifi", "source": "nmcli"}
        except WirelessError:
            pass
    return {"interfaces": list(out.values())}


def scan_nmcli() -> Dict:
    fields = "IN-USE,SSID,BSSID,CHAN,RATE,SIGNAL,BARS,SECURITY"
    text = _run(["nmcli", "-t", "-f", fields, "dev", "wifi", "list", "--rescan", "no"], timeout=45)
    aps = []
    for line in text.splitlines():
        # nmcli escapes ':' as \\:. Split conservatively, then restore escapes.
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        while len(parts) < 8:
            parts.append("")
        aps.append({
            "in_use": parts[0] == "*",
            "ssid": parts[1],
            "bssid": parts[2],
            "channel": parts[3],
            "rate": parts[4],
            "signal": parts[5],
            "bars": parts[6],
            "security": parts[7],
        })
    return {"method": "nmcli", "aps": aps, "raw": text}


def scan_iw(iface: str) -> Dict:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface or ""):
        raise WirelessError("Invalid wireless interface")
    text = _run(["iw", "dev", iface, "scan"], timeout=60)
    aps = []
    current = None
    for line in text.splitlines():
        m = re.match(r"BSS\s+([0-9a-fA-F:]{17})", line)
        if m:
            if current:
                aps.append(current)
            current = {"bssid": m.group(1), "ssid": "", "signal_dbm": None, "channel": None, "security": []}
            continue
        if current is None:
            continue
        m = re.search(r"signal:\s+(-?[0-9.]+) dBm", line)
        if m:
            current["signal_dbm"] = float(m.group(1))
        m = re.search(r"SSID:\s*(.*)$", line)
        if m:
            current["ssid"] = m.group(1).strip()
        if "WPA:" in line or "WPA2" in line or "WPA3" in line:
            current["security"].append(line.strip())
        m = re.search(r"DS Parameter set: channel (\d+)", line)
        if m:
            current["channel"] = int(m.group(1))
    if current:
        aps.append(current)
    return {"method": "iw", "interface": iface, "aps": aps, "raw": text}


def link(iface: str) -> Dict:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface or ""):
        raise WirelessError("Invalid wireless interface")
    text = _run(["iw", "dev", iface, "link"])
    return {"interface": iface, "raw": text, "connected": "Not connected" not in text}


def capabilities(iface: Optional[str] = None) -> Dict:
    cmd = ["iw", "list"]
    text = _run(cmd, timeout=30)
    bands = []
    for marker in ("2.4 GHz", "5 GHz", "6 GHz"):
        if marker in text:
            bands.append(marker)
    return {"interface": iface, "bands_detected": bands, "raw": text}


@dataclass
class ChainStep:
    id: str
    title: str
    primary: Callable[[], Dict]
    fallback: Optional[Callable[[], Dict]] = None


def run_chain(iface: Optional[str] = None) -> Dict:
    """Run non-destructive wireless assessment with bounded fallbacks.

    The engine never performs deauthentication, credential cracking, association abuse,
    or destructive/disruptive RF actions. If one method fails, it tries a documented
    alternate read-only discovery method and records the reason.
    """
    steps = [
        ChainStep("W1", "Interface discovery", interfaces),
        ChainStep("W2", "Radio capabilities", lambda: capabilities(iface), None),
        ChainStep("W3", "Access-point discovery", scan_nmcli, (lambda: scan_iw(iface)) if iface else None),
        ChainStep("W4", "Current link state", (lambda: link(iface)) if iface else lambda: {"skipped": "No interface selected"}, None),
    ]
    results = []
    for step in steps:
        record = {"id": step.id, "title": step.title, "status": "UNKNOWN", "method": "", "data": None, "error": None}
        try:
            data = step.primary()
            record.update(status="OK", method=getattr(step.primary, "__name__", "primary"), data=data)
        except Exception as primary_error:
            record["error"] = str(primary_error)
            if step.fallback:
                try:
                    data = step.fallback()
                    record.update(status="OK_FALLBACK", method=getattr(step.fallback, "__name__", "fallback"), data=data)
                except Exception as fallback_error:
                    record.update(status="FAILED", error=f"primary={primary_error}; fallback={fallback_error}")
            else:
                record["status"] = "FAILED"
        results.append(record)
    return {
        "engine": "ASEP Wireless Chain",
        "mode": "bounded_non_disruptive",
        "objective": "discover and assess wireless posture using alternate read-only methods",
        "steps": results,
        "next_if_blocked": "verify interface, driver, rfkill/regulatory state, or obtain explicit authorization for a different test profile",
    }
