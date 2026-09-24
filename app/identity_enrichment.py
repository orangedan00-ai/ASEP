"""Local identity enrichment for discovered LAN hosts.

Vendor resolution prefers locally installed authoritative-ish databases shipped
with Nmap/arp-scan so ASEP can work in isolated labs. Hostname resolution uses
Nmap reverse DNS plus the local resolver. A MAC marked locally administered is
reported as randomized/private rather than assigned to a manufacturer.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$")

_VENDOR_FILES = (
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/share/arp-scan/ieee-oui.txt"),
    Path("/usr/share/ieee-data/oui.txt"),
)


def normalize_mac(mac: str | None) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    return ":".join(raw[i:i+2] for i in range(0, 12, 2)).upper() if len(raw) == 12 else ""


def mac_flags(mac: str | None) -> dict[str, Any]:
    norm = normalize_mac(mac)
    if len(norm) != 17:
        return {"valid": False, "locally_administered": False, "multicast": False, "randomized": False}
    first = int(norm.split(":")[0], 16)
    local = bool(first & 0x02)
    multicast = bool(first & 0x01)
    return {"valid": True, "locally_administered": local, "multicast": multicast, "randomized": local and not multicast}


def _parse_vendor_file(path: Path, mac: str) -> str:
    if not path.exists():
        return ""
    compact = normalize_mac(mac).replace(":", "")
    if len(compact) != 12:
        return ""
    # Nmap format: AABBCC Vendor Name. IEEE/arp-scan files vary; accept
    # the first registered prefix that matches the address.
    prefixes = [compact[:9], compact[:8], compact[:6]]
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                token = re.split(r"\s+", s, maxsplit=1)[0].replace(":", "").replace("-", "").replace(".", "").upper()
                if token not in prefixes:
                    continue
                rest = s[len(re.split(r"\s+", s, maxsplit=1)[0]):].strip(" \t|\r")
                if rest:
                    return rest
    except OSError:
        pass
    return ""


def lookup_vendor_sources(mac: str | None) -> list[dict[str, str]]:
    """Resolve MAC vendor against every local registry available on Kali.

    A local registry is preferred because ASEP must remain useful in isolated
    labs. Multiple matching registries are retained as provenance instead of
    silently selecting one.
    """
    norm = normalize_mac(mac)
    flags = mac_flags(norm)
    if not flags["valid"]:
        return []
    if flags["multicast"]:
        return [{"source": "MAC_FLAGS", "vendor": "Multicast address", "status": "MULTICAST"}]
    if flags["locally_administered"]:
        return [{"source": "MAC_FLAGS", "vendor": "Randomized / Locally Administered", "status": "LOCAL_ADMIN"}]
    matches = []
    for path in _VENDOR_FILES:
        vendor = _parse_vendor_file(path, norm)
        if vendor:
            matches.append({"source": str(path), "vendor": vendor, "status": "MATCH"})
    return matches


def lookup_vendor(mac: str | None) -> tuple[str, str]:
    norm = normalize_mac(mac)
    flags = mac_flags(norm)
    if not flags["valid"]:
        return "", "INVALID_MAC"
    if flags["multicast"]:
        return "", "MULTICAST"
    if flags["locally_administered"]:
        return "Randomized / Locally Administered", "LOCAL_ADMIN"
    matches = lookup_vendor_sources(norm)
    if matches:
        return matches[0]["vendor"], matches[0]["source"] if matches[0]["source"] == "MAC_FLAGS" else "LOCAL_REGISTRY"
    return "Unknown manufacturer", "NOT_FOUND"


def reverse_hostname(ip: str | None) -> tuple[str, str]:
    if not ip:
        return "", "NO_IP"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "", "INVALID_IP"
    # gethostbyaddr uses the system resolver and therefore works with lab DNS,
    # mDNS/NSS configurations where supported, without requiring Internet.
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip(".")
        if name and name != ip:
            return name, "SYSTEM_REVERSE_DNS"
    except Exception:
        pass
    try:
        p = subprocess.run(["getent", "hosts", ip], capture_output=True, text=True, timeout=2, check=False)
        if p.returncode == 0:
            parts = p.stdout.split()
            if len(parts) >= 2 and parts[0] == ip:
                return parts[1].rstrip("."), "GETENT"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "", "NOT_FOUND"


def enrich_identity(ip: str | None, mac: str | None, existing_hostname: str = "", existing_vendor: str = "") -> dict[str, Any]:
    hostname = (existing_hostname or "").strip()
    hostname_source = "NMAP" if hostname else ""
    if not hostname:
        hostname, hostname_source = reverse_hostname(ip)

    vendor = (existing_vendor or "").strip()
    vendor_source = "NMAP_OUI" if vendor else ""
    vendor_sources = []
    if vendor:
        vendor_sources.append({"source": "NMAP_OUI", "vendor": vendor, "status": "MATCH"})
    local_sources = lookup_vendor_sources(mac)
    if not vendor and local_sources:
        vendor = local_sources[0]["vendor"]
        vendor_source = "LOCAL_REGISTRY" if local_sources[0]["status"] == "MATCH" else local_sources[0]["source"]
    vendor_sources.extend(local_sources)

    flags = mac_flags(mac)
    return {
        "hostname": hostname,
        "hostname_source": hostname_source or "NOT_FOUND",
        "vendor": vendor,
        "vendor_source": vendor_source or "NOT_FOUND",
        "vendor_sources": vendor_sources,
        "mac_normalized": normalize_mac(mac),
        "mac_flags": flags,
        "identity_status": "ENRICHED" if (hostname or vendor) else "PARTIAL",
    }


def infer_network_role(ip: str = "", hostname: str = "", vendor: str = "", ports=None, gateway: str = "", is_local: bool = False) -> dict[str, Any]:
    """Infer logical network role from routing, identity and observed services.

    MAC/OUI alone is never treated as proof of a network role.
    """
    ports = ports or []
    text = " ".join((hostname or "", vendor or "")).lower()
    pnums = {str(p.get("port")) for p in ports if isinstance(p, dict)}
    if is_local:
        return {"role": "ASEP Host", "confidence": "high", "basis": "local interface"}
    if gateway and ip == gateway:
        return {"role": "Gateway / Router", "confidence": "high", "basis": "default route gateway"}
    if any(x in text for x in ("firewall", "fortigate", "fortinet", "palo alto", "checkpoint", "sonicwall")):
        return {"role": "Firewall", "confidence": "medium", "basis": "vendor/hostname"}
    if any(x in text for x in ("switch", "catalyst", "managed-switch", "core-", "dist-")):
        return {"role": "Network Switch", "confidence": "medium", "basis": "vendor/hostname"}
    if any(x in text for x in ("ap", "access-point", "unifi", "wifi", "wlan")):
        return {"role": "Wireless Access Point", "confidence": "medium", "basis": "vendor/hostname"}
    if "printer" in text or "print" in text or "9100" in pnums:
        return {"role": "Printer", "confidence": "medium", "basis": "hostname/service"}
    if any(x in text for x in ("nas", "synology", "qnap", "diskstation")):
        return {"role": "NAS / Storage", "confidence": "medium", "basis": "vendor/hostname"}
    if any(x in pnums for x in ("53", "161", "179")) and not any(x in pnums for x in ("445", "3389")):
        return {"role": "Network Infrastructure", "confidence": "low", "basis": "observed infrastructure services"}
    if any(x in pnums for x in ("445", "3389", "5985", "5986")):
        return {"role": "Endpoint / Windows Host", "confidence": "medium", "basis": "observed Windows services"}
    if any(x in pnums for x in ("22", "80", "443", "8080", "8443")):
        return {"role": "Server / Host", "confidence": "low", "basis": "observed services"}
    return {"role": "Unknown", "confidence": "low", "basis": "insufficient evidence"}


def infer_asset_type(vendor: str = "", hostname: str = "", role: str = "", ports=None, ip: str = "") -> dict[str, Any]:
    """Infer a human-readable asset category from multiple observations.

    MAC/OUI identifies an organization/manufacturer, not an exact device
    form-factor. Therefore the result is explicitly an inference with a
    confidence level rather than a hardware fact.
    """
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    r = (role or "").lower()
    ports = ports or []
    portnums = {str(x.get("port")) for x in ports if isinstance(x, dict)}
    text = " ".join((v, h, r))

    if any(x in text for x in ("firewall", "fortigate", "fortinet", "palo alto", "checkpoint", "sophos firewall", "sonicwall", "watchguard")):
        return {"type": "Firewall", "confidence": "medium", "basis": "vendor/hostname/role"}
    if any(x in text for x in ("router", "gateway", "mikrotik", "ubiquiti", "cisco", "juniper", "aruba", "netgear router", "d-link")) or r in {"router", "gateway"}:
        return {"type": "Router / Gateway", "confidence": "medium", "basis": "vendor/role/hostname"}
    if any(x in text for x in ("switch", "managed switch", "catalyst")):
        return {"type": "Network Switch", "confidence": "medium", "basis": "vendor/hostname/role"}
    if any(x in text for x in ("access point", "wireless ap", "wifi ap", "unifi", "accesspoint")):
        return {"type": "Wireless Access Point", "confidence": "medium", "basis": "vendor/hostname/role"}
    if "printer" in text or "print" in text or "9100" in portnums:
        return {"type": "Printer", "confidence": "medium", "basis": "hostname/service/vendor"}
    if any(x in text for x in ("nas", "synology", "qnap", "storage", "diskstation")):
        return {"type": "NAS / Storage", "confidence": "medium", "basis": "vendor/hostname/service"}

    # Mobile phone / Android detection. MAC/OUI vendor alone is a weak
    # signal here -- e.g. Samsung and Xiaomi also make TVs, and Motorola/
    # Nokia/Google/Apple have large non-phone product lines -- so only a
    # short list of overwhelmingly phone-first vendors is used for the
    # vendor-only (low confidence) path. A hostname pattern (how phones
    # typically self-announce over DHCP, e.g. "Johns-iPhone", "android-
    # a1b2c3d4", "Galaxy-S21") is treated as medium confidence and is also
    # used to recover a brand for vendors (Apple, Google, Motorola, Nokia)
    # deliberately excluded from the vendor-only path.
    _phone_hostname_brand = (
        ("iphone", "Apple (iPhone)"), ("ipad", "Apple (iPad)"), ("galaxy", "Samsung"),
        ("redmi", "Xiaomi (Redmi)"), ("xiaomi", "Xiaomi"), ("pixel", "Google (Pixel)"),
        ("huawei", "Huawei"), ("honor", "Honor"), ("oneplus", "OnePlus"), ("oppo", "OPPO"),
        ("vivo", "Vivo"), ("realme", "Realme"), ("motorola", "Motorola"), ("moto g", "Motorola"),
        ("nokia", "Nokia"),
    )
    _phone_vendor_brand = (
        ("samsung", "Samsung"), ("xiaomi", "Xiaomi"), ("huawei", "Huawei"), ("honor", "Honor"),
        ("oneplus", "OnePlus"), ("oppo", "OPPO"), ("vivo", "Vivo"), ("realme", "Realme"),
    )
    hostname_brand = next((brand for kw, brand in _phone_hostname_brand if kw in h), None)
    hostname_generic_hit = any(x in h for x in ("android", "-phone", "smartphone"))
    vendor_brand = next((brand for kw, brand in _phone_vendor_brand if kw in v), None)
    if hostname_brand or hostname_generic_hit:
        brand = hostname_brand or vendor_brand or "Unknown (hostname pattern only, no vendor match)"
        return {"type": "Mobile Phone", "confidence": "medium", "basis": "hostname pattern", "brand": brand}
    if vendor_brand:
        return {
            "type": "Mobile Phone", "confidence": "low",
            "basis": "vendor OUI only -- this manufacturer also makes non-phone devices (e.g. TVs, appliances); "
                     "not confirmed by hostname",
            "brand": vendor_brand,
        }

    if any(x in text for x in ("server", "linux", "ubuntu", "debian", "centos", "red hat")) or any(x in portnums for x in {"22", "25", "53", "110", "143", "443", "3306", "5432", "6379", "8080"}):
        return {"type": "Server / Host", "confidence": "low", "basis": "hostname/service/vendor"}
    if any(x in text for x in ("laptop", "notebook", "thinkpad", "latitude", "elitebook", "probook", "macbook")):
        return {"type": "Laptop / Endpoint", "confidence": "medium", "basis": "hostname/vendor"}
    if any(x in text for x in ("lenovo", "dell", "hewlett", "hp", "asus", "acer", "apple", "microsoft")) or any(x in portnums for x in {"135", "139", "445", "3389"}):
        return {"type": "PC / Endpoint", "confidence": "low", "basis": "vendor/service"}
    return {"type": "Network Host", "confidence": "low", "basis": "available identity evidence"}
