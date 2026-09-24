import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from .scope import assert_target

class WindowsFingerprintError(Exception):
    pass

SCRIPTS = ["smb-os-discovery","smb-protocols","smb2-security-mode","rdp-enum-encryption","ldap-rootdse","rpcinfo"]


def _table(node):
    result = {}
    for e in node.findall("elem"):
        key = e.attrib.get("key", "value")
        result[key] = e.text or ""
    for t in node.findall("table"):
        key = t.attrib.get("key", "table")
        result[key] = _table(t)
    return result


def _script_data(node):
    out = {}
    for sc in list(node.findall("script")) + list(node.findall("hostscript/script")):
        sid = sc.attrib.get("id", "")
        data = {"output": sc.attrib.get("output", "")}
        tables = sc.findall("table")
        if tables:
            data["table"] = _table(tables[0]) if len(tables) == 1 else [_table(t) for t in tables]
        out[sid] = data
    return out


def _flatten(obj, prefix=""):
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            items.extend(_flatten(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_flatten(v, f"{prefix}[{i}]"))
    else:
        items.append((prefix, str(obj)))
    return items


def _script_text(script):
    if not script:
        return ""
    chunks = [str(script.get("output", ""))]
    chunks.extend(f"{k}: {v}" for k, v in _flatten(script.get("table", {})))
    return "\n".join(chunks)


def _find_value(text, keys):
    for key in keys:
        m = __import__("re").search(rf"(?im)^\s*{__import__('re').escape(key)}\s*[:=]\s*(.+?)\s*$", text)
        if m:
            return m.group(1).strip()
    return ""


def _parse_signing(scripts):
    text = "\n".join(_script_text(scripts.get(k, {})) for k in ("smb2-security-mode", "smb-protocols")).lower()
    # Prefer explicit required state over enabled state.
    if any(x in text for x in ("message signing required: true", "signing required: true", "message_signing_required: true", "required: true")):
        return "required"
    if any(x in text for x in ("message signing enabled: true", "signing enabled: true", "message_signing_enabled: true", "signing: enabled")):
        return "enabled"
    if any(x in text for x in ("message signing enabled: false", "signing enabled: false", "message_signing_enabled: false", "signing: disabled")):
        return "disabled"
    if "required" in text and "true" in text:
        return "required"
    return "unknown"


def _parse(xml_text):
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        raise WindowsFingerprintError("No host returned by Nmap")
    addresses = [a.attrib.get("addr") for a in host.findall("address") if a.attrib.get("addr")]
    hostnames = [x.attrib.get("name") for x in host.findall("hostnames/hostname") if x.attrib.get("name")]
    ports = []
    for p in host.findall("ports/port"):
        st, svc = p.find("state"), p.find("service")
        ports.append({"port":p.attrib.get("portid"),"protocol":p.attrib.get("protocol","tcp"),"state":st.attrib.get("state") if st is not None else "","service":svc.attrib.get("name","") if svc is not None else "","product":svc.attrib.get("product","") if svc is not None else "","version":svc.attrib.get("version","") if svc is not None else "","scripts":_script_data(p)})
    os_matches = [{"name":m.attrib.get("name",""),"accuracy":m.attrib.get("accuracy","")} for m in host.findall("os/osmatch")]
    scripts = _script_data(host)
    smb = scripts.get("smb-os-discovery", {})
    smb_text = _script_text(smb)
    # Nmap emits domain/workgroup under script tables on different versions; retain raw + normalized fields.
    hostname = hostnames[0] if hostnames else _find_value(smb_text, ["Computer name", "Computer Name", "Server name", "NetBIOS computer name"])
    domain = _find_value(smb_text, ["Domain name", "Domain Name", "Forest name", "Domain"])
    workgroup = _find_value(smb_text, ["Workgroup", "Workgroup name", "NetBIOS domain name"])
    services = {str(p["port"]): p for p in ports if p.get("state") == "open"}
    windows_ports = {"smb":[p for p in ("445","139") if p in services],"rpc":[p for p in ("135",) if p in services],"winrm":[p for p in ("5985","5986") if p in services],"rdp":[p for p in ("3389",) if p in services],"ldap":[p for p in ("389","636","3268","3269") if p in services]}
    return {"addresses":addresses,"hostname":hostname,"hostnames":hostnames,"domain":domain,"workgroup":workgroup,"os_matches":os_matches,"scripts":scripts,"ports":ports,"services":windows_ports,"smb_signing":_parse_signing(scripts),"smb_os_discovery":smb_text,"raw_xml":xml_text}


def fingerprint(cfg, target, timeout=900):
    assert_target(cfg, target)
    if not shutil.which("nmap"):
        raise WindowsFingerprintError("nmap is not installed")
    with tempfile.TemporaryDirectory(prefix="asep-winfp-") as td:
        xml_path=Path(td)/"fingerprint.xml"
        cmd=["nmap","-n","-sV","-O","--osscan-guess","-p","135,139,389,445,636,3268,3269,3389,5985,5986","--script",",".join(SCRIPTS),"-oX",str(xml_path),target]
        try:
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=min(int(timeout),1200),check=False)
        except subprocess.TimeoutExpired as e:
            raise WindowsFingerprintError("Windows fingerprint timeout") from e
        if p.returncode != 0:
            raise WindowsFingerprintError(p.stderr.strip() or "Nmap Windows fingerprint failed")
        result=_parse(xml_path.read_text(encoding="utf-8",errors="replace"))
        text=(p.stdout+" "+p.stderr+" "+result.get("smb_os_discovery","")).lower()
        result["windows_indicator"]=bool(result["services"]["smb"] or result["services"]["rpc"] or result["services"]["winrm"] or result["services"]["rdp"] or "microsoft" in text or "windows" in text)
        result.update({"command":cmd,"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr})
        return result
