import shutil

TOOLS = {
    "nmap": {"category":"network", "binary":"nmap", "apt_package":"nmap", "purpose":"Host, port, service and OS discovery", "risk":"low", "profiles":["quick","service","service_full"]},
    "ip-neigh": {"category":"network", "binary":"ip", "apt_package":"iproute2", "purpose":"Local neighbor/ARP evidence", "risk":"low", "profiles":["neighbors"]},
    "nmcli": {"category":"wireless", "binary":"nmcli", "apt_package":"network-manager", "purpose":"Wi-Fi interfaces, APs and link state", "risk":"low", "profiles":["wifi"]},
    "iw": {"category":"wireless", "binary":"iw", "apt_package":"iw", "purpose":"Wireless radio and scan evidence", "risk":"low", "profiles":["iw"]},
    "kismet": {"category":"wireless", "binary":"kismet", "apt_package":"kismet", "purpose":"Wireless device/network discovery", "risk":"medium", "profiles":["inventory"]},
    "dnsrecon": {"category":"dns", "binary":"dnsrecon", "apt_package":"dnsrecon", "purpose":"DNS enumeration evidence", "risk":"low", "profiles":["dns"]},
    "netdiscover": {"category":"network", "binary":"netdiscover", "apt_package":"netdiscover", "purpose":"ARP-based LAN discovery", "risk":"low", "profiles":["lan"]},
    "arp-scan": {"category":"network", "binary":"arp-scan", "apt_package":"arp-scan", "purpose":"Layer-2 host discovery", "risk":"low", "profiles":["lan"]},
    "httpx": {"category":"web", "binary":"httpx-toolkit", "apt_package":"httpx-toolkit", "purpose":"HTTP service probing and technology evidence", "risk":"low", "profiles":["http"]},
    "whatweb": {"category":"web", "binary":"whatweb", "apt_package":"whatweb", "purpose":"Web technology fingerprinting", "risk":"low", "profiles":["web"]},
    "nikto": {"category":"web", "binary":"nikto", "apt_package":"nikto", "purpose":"Web server security checks", "risk":"medium", "profiles":["web"]},
    "nuclei": {"category":"vulnerability", "binary":"nuclei", "apt_package":"nuclei", "purpose":"Template-based vulnerability assessment", "risk":"medium", "profiles":["vuln"]},
    "sslscan": {"category":"tls", "binary":"sslscan", "apt_package":"sslscan", "purpose":"TLS configuration evidence", "risk":"low", "profiles":["tls"]},
    "enum4linux": {"category":"identity", "binary":"enum4linux", "apt_package":"enum4linux", "purpose":"SMB/Windows enumeration", "risk":"medium", "profiles":["smb"]},
    "netexec": {"category":"identity", "binary":"nxc", "apt_package":"netexec", "purpose":"Windows/SMB/LDAP assessment", "risk":"medium", "profiles":["smb","ldap"]},
    "tshark": {"category":"network", "binary":"tshark", "apt_package":"tshark", "purpose":"Packet evidence and protocol analysis", "risk":"low", "profiles":["capture"]},
    "tcpdump": {"category":"network", "binary":"tcpdump", "apt_package":"tcpdump", "purpose":"Packet capture evidence", "risk":"low", "profiles":["capture"]},
}

def inventory():
    out=[]
    for name, meta in TOOLS.items():
        path=shutil.which(meta["binary"])
        out.append({"name":name, **meta, "installed":bool(path), "path":path or ""})
    return out

def get_tool(name):
    if name not in TOOLS:
        raise ValueError(f"Unknown tool: {name}")
    return TOOLS[name]
