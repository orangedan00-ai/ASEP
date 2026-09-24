import sqlite3
from pathlib import Path
from datetime import datetime, timezone

def db_path(cfg):
    path = Path(cfg.get("data_root", cfg["root"])) / "data" / "asep.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def connect(cfg):
    con = sqlite3.connect(db_path(cfg))
    con.row_factory = sqlite3.Row
    return con

def init_db(cfg):
    con = connect(cfg)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        evidence_type TEXT NOT NULL,
        target TEXT NOT NULL,
        summary TEXT,
        data TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        status TEXT NOT NULL,
        details TEXT
    );

    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL UNIQUE,
        name TEXT,
        role TEXT,
        state TEXT,
        scope_status TEXT,
        mac TEXT,
        vendor TEXT,
        interface TEXT,
        source TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS discovery_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        network TEXT NOT NULL,
        interface TEXT,
        method TEXT,
        active_count INTEGER DEFAULT 0,
        new_count INTEGER DEFAULT 0,
        known_count INTEGER DEFAULT 0,
        error TEXT,
        data TEXT
    );

    CREATE TABLE IF NOT EXISTS demo_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        target TEXT NOT NULL,
        controller_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        os TEXT NOT NULL,
        os_confidence TEXT,
        username TEXT NOT NULL,
        privilege TEXT,
        creation_result TEXT,
        validation_result TEXT,
        status TEXT NOT NULL DEFAULT 'DEMO_ACCOUNT_CREATED',
        cleanup_state TEXT NOT NULL DEFAULT 'PENDING_OPERATOR_CONFIRMATION',
        cleanup_at TEXT,
        cleanup_result TEXT,
        cleanup_by TEXT
    );

    CREATE TABLE IF NOT EXISTS skill_registry (        skill_id TEXT PRIMARY KEY,
        skill_number INTEGER,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        category TEXT,
        description TEXT,
        source TEXT,
        file_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'enabled',
        enabled INTEGER NOT NULL DEFAULT 1,
        built_in INTEGER NOT NULL DEFAULT 0,
        installed_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        tags TEXT,
        dependencies TEXT,
        capabilities TEXT
    );

    CREATE TABLE IF NOT EXISTS skill_registry_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        skill_id TEXT NOT NULL,
        skill_number INTEGER,
        name TEXT,
        version TEXT,
        category TEXT,
        description TEXT,
        source TEXT,
        file_path TEXT,
        sha256 TEXT,
        status TEXT,
        enabled INTEGER,
        built_in INTEGER,
        installed_at TEXT,
        updated_at TEXT,
        tags TEXT,
        dependencies TEXT,
        capabilities TEXT,
        superseded_at TEXT NOT NULL,
        superseded_reason TEXT
    );

    CREATE TABLE IF NOT EXISTS service_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        target TEXT NOT NULL,
        network TEXT,
        profile TEXT NOT NULL,
        reason TEXT,
        command TEXT,
        raw_xml TEXT,
        port_count INTEGER DEFAULT 0,
        service_count INTEGER DEFAULT 0,
        error TEXT
    );

    CREATE TABLE IF NOT EXISTS service_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        detected_at TEXT NOT NULL,
        target TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        state TEXT,
        service TEXT,
        product TEXT,
        version TEXT,
        extrainfo TEXT,
        tunnel TEXT,
        method TEXT,
        confidence INTEGER,
        cpe TEXT,
        reason TEXT,
        source TEXT NOT NULL,
        raw TEXT,
        UNIQUE(scan_id,target,port,protocol),
        FOREIGN KEY(scan_id) REFERENCES service_scans(id)
    );
    """)
    con.commit()
    con.close()



def reset_network_state(cfg):
    """Remove network-dependent inventory from the previous environment.

    Audit history, configuration, skills and application source are retained.
    Targets/evidence/discovery runs are environment-derived and must not leak
    from one laptop/network session into the next.
    """
    con = connect(cfg)
    con.execute("DELETE FROM evidence")
    con.execute("DELETE FROM targets")
    con.execute("DELETE FROM discovery_runs")
    con.execute("DELETE FROM service_inventory")
    con.execute("DELETE FROM service_scans")
    con.commit()
    con.close()


def create_service_scan(cfg, target, network, profile, reason, command, started_at=None):
    import json
    con = connect(cfg)
    cur = con.execute(
        "INSERT INTO service_scans(started_at,status,target,network,profile,reason,command) VALUES(?,?,?,?,?,?,?)",
        (started_at or datetime.now(timezone.utc).isoformat(), "RUNNING", target, network or "", profile, reason or "", json.dumps(command or [], ensure_ascii=False)),
    )
    con.commit(); scan_id = cur.lastrowid; con.close()
    return int(scan_id)

def finish_service_scan(cfg, scan_id, status, raw_xml="", port_count=0, service_count=0, error=""):
    con = connect(cfg)
    con.execute(
        "UPDATE service_scans SET finished_at=?,status=?,raw_xml=?,port_count=?,service_count=?,error=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), status, raw_xml or "", int(port_count), int(service_count), error or "", int(scan_id)),
    )
    con.commit(); con.close()

def add_service_inventory(cfg, scan_id, target, ports, source="nmap-deep-full"):
    import json
    now = datetime.now(timezone.utc).isoformat()
    con = connect(cfg)
    rows = []
    for p in ports or []:
        try:
            port = int(p.get("port"))
        except Exception:
            continue
        rows.append((
            int(scan_id), now, target, port, str(p.get("protocol") or "tcp"), str(p.get("state") or ""),
            str(p.get("service") or ""), str(p.get("product") or ""), str(p.get("version") or ""),
            str(p.get("extrainfo") or ""), str(p.get("tunnel") or ""), str(p.get("method") or ""),
            int(p.get("confidence")) if str(p.get("confidence") or "").isdigit() else None,
            str(p.get("cpe") or ""), str(p.get("reason") or ""), source, json.dumps(p, ensure_ascii=False),
        ))
    con.executemany(
        """INSERT OR REPLACE INTO service_inventory
        (scan_id,detected_at,target,port,protocol,state,service,product,version,extrainfo,tunnel,method,confidence,cpe,reason,source,raw)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
    con.commit(); con.close()
    return len(rows)

def list_service_inventory(cfg, target=None, limit=5000, latest_only=True):
    con = connect(cfg)
    if latest_only:
        sql = """SELECT si.*, ss.finished_at, ss.status AS scan_status, ss.profile, ss.reason AS scan_reason
                 FROM service_inventory si JOIN service_scans ss ON ss.id=si.scan_id
                 WHERE ss.id=(SELECT MAX(s2.id) FROM service_scans s2 WHERE s2.target=si.target AND s2.status='COMPLETE')"""
        params = []
        if target:
            sql += " AND si.target=?"; params.append(target)
        sql += " ORDER BY si.target, si.protocol, si.port LIMIT ?"; params.append(limit)
    else:
        sql = "SELECT * FROM service_inventory"; params=[]
        if target:
            sql += " WHERE target=?"; params.append(target)
        sql += " ORDER BY detected_at DESC, target, protocol, port LIMIT ?"; params.append(limit)
    rows=con.execute(sql, params).fetchall(); con.close()
    return [dict(r) for r in rows]

def latest_service_scan(cfg, target):
    con=connect(cfg)
    row=con.execute("SELECT * FROM service_scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)).fetchone()
    con.close(); return dict(row) if row else None

def latest_service_scan_xml(cfg, target):
    row=latest_service_scan(cfg, target)
    return (row or {}).get("raw_xml", "")


def add_evidence(cfg, evidence_type, target, summary, data):
    con = connect(cfg)
    con.execute(
        "INSERT INTO evidence(created_at,evidence_type,target,summary,data) VALUES(?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), evidence_type, target, summary, data),
    )
    con.commit()
    con.close()

def list_evidence(cfg, limit=50, include_data=False):
    con = connect(cfg)
    columns = "id,created_at,evidence_type,target,summary,data" if include_data else "id,created_at,evidence_type,target,summary"
    rows = con.execute(
        f"SELECT {columns} FROM evidence ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

def get_evidence(cfg, evidence_id):
    con = connect(cfg)
    row = con.execute(
        "SELECT * FROM evidence WHERE id=?", (evidence_id,)
    ).fetchone()
    con.close()
    return dict(row) if row else None

def add_audit(cfg, action, target, status, details=""):
    con = connect(cfg)
    con.execute(
        "INSERT INTO audit(created_at,action,target,status,details) VALUES(?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), action, target, status, details),
    )
    con.commit()
    con.close()


def upsert_target(cfg, target):
    now = datetime.now(timezone.utc).isoformat()
    con = connect(cfg)
    existing = con.execute("SELECT id, first_seen FROM targets WHERE address=?", (target["address"],)).fetchone()
    metadata = target.get("metadata", {})
    import json
    if existing:
        con.execute(
            """UPDATE targets SET name=?,role=?,state=?,scope_status=?,mac=?,vendor=?,interface=?,source=?,last_seen=?,metadata=? WHERE address=?""",
            (target.get("name", ""), target.get("role", "unknown"), target.get("state", "unknown"),
             target.get("scope_status", "LOCAL-CANDIDATE"), target.get("mac"), target.get("vendor"),
             target.get("interface"), target.get("source", "network-discovery"), now,
             json.dumps(metadata, ensure_ascii=False), target["address"]),
        )
        created = False
    else:
        con.execute(
            """INSERT INTO targets(address,name,role,state,scope_status,mac,vendor,interface,source,first_seen,last_seen,metadata)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (target["address"], target.get("name", ""), target.get("role", "unknown"), target.get("state", "unknown"),
             target.get("scope_status", "LOCAL-CANDIDATE"), target.get("mac"), target.get("vendor"), target.get("interface"),
             target.get("source", "network-discovery"), now, now, json.dumps(metadata, ensure_ascii=False)),
        )
        created = True
    con.commit()
    con.close()
    return {"created": created, "address": target["address"]}

def list_targets(cfg, limit=500):
    con = connect(cfg)
    rows = con.execute("SELECT * FROM targets ORDER BY address LIMIT ?", (limit,)).fetchall()
    con.close()
    import json
    out=[]
    for row in rows:
        item=dict(row)
        try:
            item["metadata"] = json.loads(item.get("metadata") or "{}")
        except Exception:
            item["metadata"] = {}
        out.append(item)
    return out

def create_discovery_run(cfg, network, interface, method):
    con=connect(cfg)
    cur=con.execute(
        "INSERT INTO discovery_runs(started_at,status,network,interface,method) VALUES(?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), "RUNNING", network, interface, method),
    )
    con.commit(); run_id=cur.lastrowid; con.close()
    return int(run_id)

def finish_discovery_run(cfg, run_id, status, active_count=0, new_count=0, known_count=0, error="", data=None):
    import json
    con=connect(cfg)
    con.execute(
        """UPDATE discovery_runs SET finished_at=?,status=?,active_count=?,new_count=?,known_count=?,error=?,data=? WHERE id=?""",
        (datetime.now(timezone.utc).isoformat(), status, active_count, new_count, known_count, error,
         json.dumps(data or {}, ensure_ascii=False), run_id),
    )
    con.commit(); con.close()

def list_discovery_runs(cfg, limit=30):
    con=connect(cfg)
    rows=con.execute("SELECT * FROM discovery_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]

def get_skill(cfg, skill_id):
    con = connect(cfg)
    row = con.execute("SELECT * FROM skill_registry WHERE skill_id=?", (skill_id,)).fetchone()
    con.close()
    return dict(row) if row else None

def list_skills(cfg, enabled_only=False):
    con = connect(cfg)
    q = "SELECT * FROM skill_registry"
    if enabled_only:
        q += " WHERE enabled=1"
    q += " ORDER BY skill_number ASC, skill_id ASC"
    rows = con.execute(q).fetchall()
    con.close()
    return [dict(r) for r in rows]

def skill_registry_count(cfg):
    con = connect(cfg)
    n = con.execute("SELECT COUNT(*) FROM skill_registry").fetchone()[0]
    con.close()
    return n

def upsert_skill(cfg, skill, superseded_reason=""):
    """Insert a new skill row, or replace an existing one -- archiving the
    row being replaced into skill_registry_history first (never a silent
    overwrite; see master doc Section 8). `skill` is a dict matching the
    skill_registry columns (skill_id, skill_number, name, version, category,
    description, source, file_path, sha256, status, enabled, built_in,
    tags, dependencies, capabilities -- the last three as JSON strings).
    """
    now = datetime.now(timezone.utc).isoformat()
    con = connect(cfg)
    existing = con.execute("SELECT * FROM skill_registry WHERE skill_id=?", (skill["skill_id"],)).fetchone()
    if existing:
        e = dict(existing)
        con.execute(
            """INSERT INTO skill_registry_history
               (skill_id, skill_number, name, version, category, description, source, file_path, sha256,
                status, enabled, built_in, installed_at, updated_at, tags, dependencies, capabilities,
                superseded_at, superseded_reason)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (e["skill_id"], e["skill_number"], e["name"], e["version"], e["category"], e["description"],
             e["source"], e["file_path"], e["sha256"], e["status"], e["enabled"], e["built_in"],
             e["installed_at"], e["updated_at"], e["tags"], e["dependencies"], e["capabilities"],
             now, superseded_reason or "replaced by new upload"),
        )
        installed_at = e["installed_at"]
    else:
        installed_at = now
    con.execute(
        """INSERT INTO skill_registry
           (skill_id, skill_number, name, version, category, description, source, file_path, sha256,
            status, enabled, built_in, installed_at, updated_at, tags, dependencies, capabilities)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(skill_id) DO UPDATE SET
             skill_number=excluded.skill_number, name=excluded.name, version=excluded.version,
             category=excluded.category, description=excluded.description, source=excluded.source,
             file_path=excluded.file_path, sha256=excluded.sha256, status=excluded.status,
             enabled=excluded.enabled, built_in=excluded.built_in, updated_at=excluded.updated_at,
             tags=excluded.tags, dependencies=excluded.dependencies, capabilities=excluded.capabilities""",
        (skill["skill_id"], skill.get("skill_number"), skill["name"], skill["version"], skill.get("category", ""),
         skill.get("description", ""), skill.get("source", "upload"), skill["file_path"], skill["sha256"],
         skill.get("status", "enabled"), int(skill.get("enabled", 1)), int(skill.get("built_in", 0)),
         installed_at, now, skill.get("tags", "[]"), skill.get("dependencies", "[]"), skill.get("capabilities", "[]")),
    )
    con.commit(); con.close()
    return {"skill_id": skill["skill_id"], "was_update": bool(existing), "previous_version": dict(existing)["version"] if existing else None}

def set_skill_enabled(cfg, skill_id, enabled):
    con = connect(cfg)
    con.execute("UPDATE skill_registry SET enabled=?, updated_at=? WHERE skill_id=?",
                (int(enabled), datetime.now(timezone.utc).isoformat(), skill_id))
    con.commit(); con.close()

def create_demo_account(cfg, target, controller_id, session_id, os_name, os_confidence, username, privilege, creation_result, validation_result):
    """Record a demo account. Status is always DEMO_ACCOUNT_CREATED.
    cleanup_state is always PENDING_OPERATOR_CONFIRMATION -- never changes
    automatically. The record persists across ASEP restarts, session loss,
    and assessment completion (Stage 2 Section 22 requirement).
    """
    now = datetime.now(timezone.utc).isoformat()
    con = connect(cfg)
    cur = con.execute(
        """INSERT INTO demo_accounts
           (created_at, target, controller_id, session_id, os, os_confidence, username, privilege,
            creation_result, validation_result, status, cleanup_state)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (now, target, str(controller_id), str(session_id), os_name, os_confidence, username, privilege,
         creation_result, validation_result, "DEMO_ACCOUNT_CREATED", "PENDING_OPERATOR_CONFIRMATION"),
    )
    account_id = cur.lastrowid
    con.commit(); con.close()
    return account_id

def list_demo_accounts(cfg, include_cleaned=False):
    con = connect(cfg)
    if include_cleaned:
        rows = con.execute("SELECT * FROM demo_accounts ORDER BY id DESC").fetchall()
    else:
        rows = con.execute("SELECT * FROM demo_accounts WHERE cleanup_state != 'CLEANUP_VERIFIED' ORDER BY id DESC").fetchall()
    con.close()
    return [dict(r) for r in rows]

def get_demo_account(cfg, account_id):
    con = connect(cfg)
    row = con.execute("SELECT * FROM demo_accounts WHERE id=?", (int(account_id),)).fetchone()
    con.close()
    return dict(row) if row else None

def record_demo_cleanup(cfg, account_id, cleanup_state, cleanup_result, cleanup_by="operator"):
    """Called ONLY by the explicit operator confirmation endpoint.
    cleanup_state must be CLEANUP_VERIFIED or CLEANUP_FAILED.
    """
    now = datetime.now(timezone.utc).isoformat()
    con = connect(cfg)
    con.execute(
        """UPDATE demo_accounts
           SET cleanup_state=?, cleanup_at=?, cleanup_result=?, cleanup_by=?
           WHERE id=?""",
        (cleanup_state, now, cleanup_result, cleanup_by, int(account_id)),
    )
    con.commit(); con.close()

def skill_history(cfg, skill_id, limit=10):
    con = connect(cfg)
    rows = con.execute("SELECT * FROM skill_registry_history WHERE skill_id=? ORDER BY id DESC LIMIT ?", (skill_id, limit)).fetchall()
    con.close()
    return [dict(r) for r in rows]
