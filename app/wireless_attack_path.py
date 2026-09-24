import ipaddress
import json
from datetime import datetime, timezone
from .db import connect


def _load_evidence(cfg):
    con = connect(cfg)
    rows = con.execute("SELECT id,created_at,evidence_type,target,summary,data FROM evidence ORDER BY id DESC LIMIT 100").fetchall()
    con.close()
    out=[]
    for r in rows:
        d=dict(r)
        try: d['payload']=json.loads(d['data'])
        except Exception: d['payload']={}
        out.append(d)
    return out


def _private_ip(value):
    try:
        ip=ipaddress.ip_address(value)
        return ip.is_private
    except Exception:
        return False


def _same_private_network(a,b,prefix=24):
    try:
        na=ipaddress.ip_network(f"{a}/{prefix}", strict=False)
        nb=ipaddress.ip_network(f"{b}/{prefix}", strict=False)
        return na==nb
    except Exception:
        return False


def _weak_security(sec):
    s=' '.join(sec) if isinstance(sec,list) else str(sec or '')
    u=s.upper()
    if not s or u in {'--','OPEN','NONE'} or 'WEP' in u:
        return True, 'Weak/absent wireless protection observed'
    if 'WPA1' in u or ('WPA ' in u and 'WPA2' not in u and 'WPA3' not in u):
        return True, 'Legacy WPA security observed'
    return False, 'No weak wireless security indicator in collected evidence'


def _latest_wireless(evidence):
    for e in evidence:
        if e['evidence_type'] == 'wireless':
            return e
        if e['evidence_type'] == 'wireless_chain':
            # Chain payload can contain W3 AP discovery data.
            for step in e['payload'].get('steps',[]):
                if step.get('id')=='W3' and step.get('data'):
                    return {'id':e['id'],'created_at':e['created_at'],'payload':step['data']}
    return None


def _local_context():
    import psutil
    interfaces=[]
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            fam = getattr(a, 'family', None)
            if getattr(fam, 'name', '') == 'AF_INET':
                if _private_ip(a.address):
                    interfaces.append({'interface':name,'ip':a.address,'netmask':a.netmask})
    return interfaces


def build_attack_paths(cfg):
    evidence=_load_evidence(cfg)
    wireless=_latest_wireless(evidence)
    nmap=next((e for e in evidence if e['evidence_type']=='nmap'),None)
    nodes=[{'id':'asep','type':'controller','label':'ASEP / Kali','status':'CONFIRMED','x':5,'y':50}]
    edges=[]
    findings=[]
    now=datetime.now(timezone.utc).isoformat()
    if not wireless:
        return {'engine':'ASEP Wireless Attack-Path Engine','generated_at':now,'status':'NO_WIRELESS_EVIDENCE','nodes':nodes,'edges':edges,'paths':[],'findings':findings,'notes':['Run Wireless Discovery or Wireless Chain first.']}

    aps=wireless['payload'].get('aps',[]) if isinstance(wireless.get('payload'),dict) else []
    local=_local_context()
    for i,ap in enumerate(aps[:20]):
        weak,reason=_weak_security(ap.get('security'))
        aid='ap_'+str(i)
        nodes.append({'id':aid,'type':'ap','label':ap.get('ssid') or '(hidden SSID)','detail':f"BSSID {ap.get('bssid','—')} · CH {ap.get('channel','—')}",'status':'INDICATOR' if weak else 'OBSERVED','weak':weak,'x':20+(i%4)*18,'y':15+(i//4)*28})
        if weak:
            findings.append({'status':'[INDICATOR]','title':'Weak wireless security indicator','target':ap.get('ssid') or ap.get('bssid','unknown'),'evidence_id':wireless.get('id'),'detail':reason})
            edges.append({'from':'asep','to':aid,'label':'wireless posture','status':'INDICATOR','confidence':'medium'})

    if not nmap:
        return {'engine':'ASEP Wireless Attack-Path Engine','generated_at':now,'status':'PARTIAL','nodes':nodes,'edges':edges,'paths':[],'findings':findings,'notes':['No Nmap evidence available; reachable-client and internal-service correlation remains unverified.']}

    hosts=nmap['payload'].get('hosts',[]) if isinstance(nmap.get('payload'),dict) else []
    # Build candidate internal services from Nmap evidence.
    service_nodes=[]
    for idx,h in enumerate(hosts[:40]):
        ip=h.get('ip') or h.get('host')
        if not ip or not _private_ip(ip):
            continue
        ports=h.get('ports',[]) or []
        if not ports:
            continue
        sid=f"host_{idx}"
        svc=[]
        for p in ports[:12]:
            svc.append(f"{p.get('port')}/{p.get('service') or p.get('name') or p.get('state','tcp')}")
        service_nodes.append((sid,ip,svc,h))

    connected=any(x.get('interface') and x.get('ip') for x in local)
    weak_aps=[n for n in nodes if n.get('type')=='ap' and n.get('weak')]
    # We can only claim reachability when a private local context and Nmap host share a /24.
    for idx,(sid,ip,svc,h) in enumerate(service_nodes):
        reachable=any(_same_private_network(ip,x['ip']) for x in local)
        status='INDICATOR' if reachable else 'UNKNOWN'
        nodes.append({'id':sid,'type':'client','label':ip,'detail':', '.join(svc),'status':status,'x':48+(idx%3)*17,'y':22+(idx//3)*28})
        if reachable:
            findings.append({'status':'[INDICATOR]','title':'Potentially reachable internal host','target':ip,'evidence_id':nmap['id'],'detail':'Private host shasep the observed local /24; this is a reachability indicator, not proof of wireless-originated access.'})
            for ap in weak_aps[:4]:
                edges.append({'from':ap['id'],'to':sid,'label':'same private segment','status':'INDICATOR','confidence':'medium'})
            # service nodes
            for j,s in enumerate(svc[:8]):
                xid=f"svc_{idx}_{j}"
                nodes.append({'id':xid,'type':'service','label':s,'status':'OBSERVED','x':66+(j%2)*15,'y':18+((idx+j)%5)*14})
                edges.append({'from':sid,'to':xid,'label':'service exposed','status':'OBSERVED','confidence':'high'})
                if any(k in s.lower() for k in ['ssh','rdp','smb','winrm','ldap','http','https']):
                    bid=f"boundary_{idx}_{j}"
                    nodes.append({'id':bid,'type':'boundary','label':'Privilege boundary','detail':'Authorization boundary requires validation','status':'HYPOTHESIS','x':86,'y':18+((idx+j)%5)*14})
                    edges.append({'from':xid,'to':bid,'label':'auth boundary','status':'HYPOTHESIS','confidence':'low'})
                    findings.append({'status':'[HYPOTHESIS]','title':'Privilege boundary requires validation','target':ip,'evidence_id':nmap['id'],'detail':f'Service {s} may expose an authentication/authorization boundary. No privilege escalation is asserted.'})

    paths=[]
    for ap in weak_aps:
        for sid,ip,svc,h in service_nodes:
            if any(e['from']==ap['id'] and e['to']==sid for e in edges):
                path=[ap['id'],sid]
                paths.append({'id':f"path_{len(paths)+1}",'status':'INDICATOR','label':'Wireless posture → internal reachability','nodes':path,'confidence':'medium','next_validation':'Confirm client association and test reachability only within authorized scope.'})
                for e in edges:
                    if e['from']==sid:
                        paths.append({'id':f"path_{len(paths)+1}",'status':'HYPOTHESIS','label':'Wireless posture → internal service → privilege boundary','nodes':[ap['id'],sid,e['to']],'confidence':'low','next_validation':'Validate service authorization and privilege boundary; do not infer compromise from exposure alone.'})

    return {'engine':'ASEP Wireless Attack-Path Engine','generated_at':now,'status':'READY','nodes':nodes,'edges':edges,'paths':paths[:20],'findings':findings[:50], 'notes':['Correlation is evidence-driven. Reachability is inferred only from collected private-network context and Nmap evidence. Privilege escalation is never assumed.','Alternative paths are generated from observed evidence; blocked/unknown stages are explicitly labeled.']}
