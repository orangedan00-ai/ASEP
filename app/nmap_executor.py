import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .scope import assert_target, assert_local_discovery_target, assert_local_discovery_host

PROFILES = {
    "quick": ["-sn", "-PE", "-PP", "-R"],
    "host_discovery_auto": ["-sn", "-R"],
    "host_discovery_arp": ["-sn", "-PR", "-R"],
    "host_discovery_icmp": ["-sn", "-PE", "-PP", "-R"],
    "host_discovery_tcp": ["-sn", "-PS80,443", "-PA80", "-R"],
    "service": ["-sV", "--top-ports", "100"],
    "service_full": ["-sV", "-p-", "--version-light"],
    # Comprehensive TCP-only inventory scan. UDP is intentionally excluded from
    # the deep inventory workflow. It is restricted by the normal scope gates.
    "deep_full": ["-sT", "-p-", "-sV", "--version-all", "--allports", "--reason", "-T4", "--max-retries", "3", "--host-timeout", "5m", "-O", "--osscan-guess"],
}

class NmapError(Exception):
    pass

def _parse_xml(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        state = status.attrib.get("state") if status is not None else "unknown"

        addresses = []
        mac = ""
        vendor = ""
        for addr in host.findall("address"):
            if addr.attrib.get("addr"):
                addresses.append(addr.attrib["addr"])
            if addr.attrib.get("addrtype") == "mac":
                mac = addr.attrib.get("addr", "")
                vendor = addr.attrib.get("vendor", "")

        hostnames = []
        hostnames_node = host.find("hostnames")
        if hostnames_node is not None:
            for hn in hostnames_node.findall("hostname"):
                if hn.attrib.get("name"):
                    hostnames.append(hn.attrib["name"])

        os_detection = {"matches": [], "classes": [], "cpe": []}
        os_node = host.find("os")
        if os_node is not None:
            for match in os_node.findall("osmatch"):
                os_detection["matches"].append({
                    "name": match.attrib.get("name", ""),
                    "accuracy": match.attrib.get("accuracy", ""),
                    "line": match.attrib.get("line", ""),
                })
                for cls in match.findall("osclass"):
                    os_detection["classes"].append({
                        "type": cls.attrib.get("type", ""),
                        "vendor": cls.attrib.get("vendor", ""),
                        "osfamily": cls.attrib.get("osfamily", ""),
                        "osgen": cls.attrib.get("osgen", ""),
                        "accuracy": cls.attrib.get("accuracy", ""),
                        "cpe": [c.text or "" for c in cls.findall("cpe")],
                    })
            os_detection["cpe"] = [c.text or "" for c in os_node.findall("osmatch/osclass/cpe") if c.text]

        ports = []
        ports_node = host.find("ports")
        if ports_node is not None:
            for port in ports_node.findall("port"):
                service = port.find("service")
                state_node = port.find("state")
                cpes = []
                if service is not None:
                    cpes = [c.attrib.get("product") or (c.text or "") for c in service.findall("cpe")]
                ports.append({
                    "port": port.attrib.get("portid"),
                    "protocol": port.attrib.get("protocol"),
                    "state": state_node.attrib.get("state") if state_node is not None else "",
                    "reason": state_node.attrib.get("reason") if state_node is not None else "",
                    "reason_ttl": state_node.attrib.get("reason_ttl") if state_node is not None else "",
                    "service": service.attrib.get("name") if service is not None else "",
                    "product": service.attrib.get("product") if service is not None else "",
                    "version": service.attrib.get("version") if service is not None else "",
                    "extrainfo": service.attrib.get("extrainfo") if service is not None else "",
                    "tunnel": service.attrib.get("tunnel") if service is not None else "",
                    "method": service.attrib.get("method") if service is not None else "",
                    "confidence": service.attrib.get("conf") if service is not None else "",
                    "cpe": ",".join(x for x in cpes if x),
                })

        hosts.append({
            "state": state,
            "addresses": addresses,
            "hostnames": hostnames,
            "mac": mac,
            "vendor": vendor,
            "os_detection": os_detection,
            "ports": ports,
        })

    return hosts

def run_nmap(cfg, target, profile, local_discovery=False):
    if local_discovery:
        # Networks are used for host discovery; individual IPs are used for
        # the automatic, evidence-producing service scan of newly observed
        # local assets. Both remain restricted to directly connected local
        # networks.
        if "/" in str(target):
            assert_local_discovery_target(cfg, target)
        else:
            assert_local_discovery_host(cfg, target)
    else:
        assert_target(cfg, target)

    if profile not in PROFILES:
        raise NmapError("Scan profile tidak dikenal.")

    args = PROFILES[profile]

    with tempfile.TemporaryDirectory(prefix="asep-nmap-") as td:
        xml_path = Path(td) / "scan.xml"

        cmd = [
            "nmap",
            "-oX", str(xml_path),
            *(args if profile.startswith("host_discovery_") or profile == "quick" else ["-n", *args]),
            target,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=360,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise NmapError("Nmap timeout setelah 900 detik.") from e
        except FileNotFoundError as e:
            raise NmapError("Nmap tidak ditemukan. Install nmap pada Kali Linux.") from e

        if proc.returncode != 0:
            # OS fingerprinting (-O) may require elevated privileges. Preserve the
            # TCP-only service inventory even when ASEP is running unprivileged by
            # retrying the same comprehensive TCP scan without OS detection.
            if profile == "deep_full" and "-O" in args:
                fallback_args = [x for x in args if x not in {"-O", "--osscan-guess"}]
                fallback_cmd = ["nmap", "-oX", str(xml_path), "-n", *fallback_args, target]
                fallback = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=360, check=False)
                if fallback.returncode == 0:
                    proc = fallback
                    args = fallback_args
                    cmd = fallback_cmd
                else:
                    raise NmapError(fallback.stderr.strip() or proc.stderr.strip() or "Nmap gagal.")
            else:
                raise NmapError(proc.stderr.strip() or "Nmap gagal.")

        xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
        parsed = _parse_xml(xml_text)

        return {
            "command": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "hosts": parsed,
            "raw_xml": xml_text,
        }
