import json, shutil, subprocess, time, ipaddress
from .scope import assert_target, ScopeError
from .tool_registry import get_tool

class ToolError(Exception): pass

# Bounded, evidence-producing profiles. No credential attacks, persistence, DoS, or destructive actions.
PROFILES = {
    "neighbors": lambda: ["ip","neigh","show"],
    "wifi": lambda: ["nmcli","-t","-f","IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY,DEVICE","device","wifi","list"],
    "iw": lambda iface: ["iw",iface,"scan"],
    "lan": lambda: ["arp-scan","--localnet"],
    "dns": lambda target: ["dnsrecon","-d",target,"-t","std"],
    "http": lambda target: ["httpx","-silent","-u",target],
    "web": lambda target: ["whatweb","--no-errors",target],
    "nikto": lambda target: ["nikto","-host",target,"-nointeractive"],
    "vuln": lambda target: ["nuclei","-u",target,"-silent","-no-interactsh"],
    "tls": lambda target: ["sslscan",target],
    "smb": lambda target: ["nxc","smb",target],
    "ldap": lambda target: ["nxc","ldap",target],
}

def _safe_target(target):
    target=str(target or "").strip()
    if not target or any(x in target for x in ["\n","\r",";","&&","|","`","$"]):
        raise ToolError("Invalid target")
    return target

def run_profile(cfg, tool_name, profile, target=None, interface=None, timeout=300):
    meta=get_tool(tool_name)
    if not shutil.which(meta["binary"]):
        raise ToolError(f"Tool not installed: {meta['binary']}")
    if profile not in meta["profiles"]:
        raise ToolError(f"Profile '{profile}' is not supported for {tool_name}")
    if target and profile not in {"neighbors","wifi","iw","lan"}:
        assert_target(cfg, target)
    if profile in {"http","web","nikto","vuln","tls","smb","ldap","dns"}:
        target=_safe_target(target)
    if profile=="iw":
        if not interface or not interface.replace('_','').replace('-','').isalnum(): raise ToolError("Invalid interface")
        cmd=PROFILES[profile](interface)
    elif profile in {"neighbors","wifi","lan"}:
        cmd=PROFILES[profile]()
    else:
        cmd=PROFILES[profile](target)
    started=time.time()
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=min(int(timeout),900),check=False)
    except subprocess.TimeoutExpired as e:
        raise ToolError(f"{tool_name} timed out") from e
    return {"tool":tool_name,"profile":profile,"command":cmd,"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr,"elapsed_sec":round(time.time()-started,2)}

def plan_for_target(cfg, target, evidence=None):
    assert_target(cfg,target)
    text=json.dumps(evidence or {},ensure_ascii=False).lower()
    plan=[]
    plan.append({"tool":"nmap","profile":"service","reason":"Establish current service/port evidence","priority":1})
    if any(x in text for x in ["http","https","80/tcp","443/tcp"]):
        plan += [
            {"tool":"httpx","profile":"http","reason":"Confirm HTTP reachability and metadata","priority":2},
            {"tool":"whatweb","profile":"web","reason":"Fingerprint web technology","priority":3},
            {"tool":"sslscan","profile":"tls","reason":"Assess TLS configuration when HTTPS is present","priority":4},
        ]
    if any(x in text for x in ["445/tcp","smb"]):
        plan += [{"tool":"netexec","profile":"smb","reason":"Collect bounded SMB/Windows service evidence","priority":3}]
    if any(x in text for x in ["389/tcp","636/tcp","ldap"]):
        plan += [{"tool":"netexec","profile":"ldap","reason":"Collect bounded LDAP service evidence","priority":3}]
    return {"target":target,"plan":sorted(plan,key=lambda x:x["priority"]),"note":"Only in-scope, bounded evidence collection is planned automatically."}
