"""ASEP Session Intelligence — Stage 2, Phase 11-13.

Immediately upon an authorized Metasploit session being obtained, ASEP
should not just report "session opened." It should profile the host, the
user context, privilege level, network interfaces, and update the attack
graph. See Stage 2 document Sections 18-20.

Separate from (and complementary to) post_session_intelligence.py, which
provides abstract recommendation logic. This module performs the actual
evidence-collection commands and builds the demo-account workflow.

Security constraints that are enforced here, not left to convention:
  - OS must be IDENTIFIED (not guessed) before any account action.
  - Privilege must be explicitly observed (not assumed from session type).
  - Demo account username is always asep_demo_<unix_timestamp> — never
    overrides existing users, never creates hidden users.
  - No automatic cleanup ever. cleanup_state = PENDING_OPERATOR_CONFIRMATION
    and stays that way until an operator explicitly calls the cleanup endpoint.
  - Dry-run/check mode (probe without acting) is always available.
"""
import re
import time
from datetime import datetime, timezone
from typing import Optional

_OS_COMMANDS = {
    # Platform → (detect_command, parse_function_name)
    "linux":   ("uname -a && id && whoami && ip addr 2>/dev/null || ifconfig 2>/dev/null", "_parse_linux_profile"),
    "windows": ("systeminfo | findstr /B \"OS Name\" & whoami /all & ipconfig /all", "_parse_windows_profile"),
    "unknown": ("uname -a 2>/dev/null; id 2>/dev/null; whoami 2>/dev/null; cmd /c ver 2>/dev/null", "_parse_generic_profile"),
}

# Demo account commands per OS — account creation only, not hidden, not persistent.
_DEMO_CREATE = {
    "linux": "useradd -m -s /bin/bash -c 'ASEP Demo Account' '{user}' && echo '{user}:{pw}' | chpasswd",
    "windows": "net user {user} {pw} /add /comment:\"ASEP Demo Account\"",
}
_DEMO_VALIDATE = {
    "linux": "id '{user}' 2>&1 | head -3",
    "windows": "net user {user} 2>&1",
}
_DEMO_CLEANUP = {
    "linux": "userdel -r '{user}' 2>&1; id '{user}' 2>&1 | head -2",
    "windows": "net user {user} /delete 2>&1",
}


def _detect_os_from_output(output: str) -> tuple[str, str]:
    """Return (platform, confidence). platform is 'linux'/'windows'/'unknown'."""
    lo = output.lower()
    if any(x in lo for x in ("linux", "ubuntu", "debian", "centos", "redhat", "kali", "alpine", "arch")):
        return "linux", "high"
    if any(x in lo for x in ("windows", "microsoft", "win32", "winnt")):
        return "windows", "high"
    if "darwin" in lo or "macos" in lo or "mac os" in lo:
        return "darwin", "medium"
    return "unknown", "low"


def _detect_privilege(output: str, platform: str) -> str:
    """Return 'root'/'administrator'/'user'/'unknown' from command output."""
    lo = output.lower()
    if platform == "linux":
        if re.search(r"\buid=0\b", lo) or re.search(r"\broot\b", lo[:200]):
            return "root"
        uid = re.search(r"uid=(\d+)", lo)
        if uid and uid.group(1) != "0":
            return "user"
    elif platform == "windows":
        if "administrators" in lo or "nt authority\\system" in lo:
            return "administrator"
        return "user"
    return "unknown"


def _detect_user(output: str, platform: str) -> str:
    if platform == "linux":
        m = re.search(r"(?:^|\n)([a-z_][a-z0-9_-]*)\s*$", output, re.M)
        if m:
            return m.group(1).strip()
        m = re.search(r"uid=\d+\(([^)]+)\)", output)
        if m:
            return m.group(1)
    elif platform == "windows":
        m = re.search(r"user name\s+(.+)", output, re.I)
        if m:
            return m.group(1).strip()
    return "unknown"


def _extract_interfaces(output: str, platform: str) -> list:
    interfaces = []
    if platform == "linux":
        # ip addr output: "N: eth0: ..."  followed by  "    inet A.B.C.D/prefix ..."
        current = None
        for line in output.splitlines():
            m = re.match(r"^\d+:\s+(\S+):", line)
            if m:
                current = m.group(1)
            m2 = re.match(r"\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m2 and current:
                interfaces.append({"name": current, "ip": m2.group(1), "prefix": m2.group(2)})
    elif platform == "windows":
        adapter = None
        for line in output.splitlines():
            if "adapter" in line.lower():
                adapter = line.strip().rstrip(":")
            m = re.match(r"\s+IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if m and adapter:
                interfaces.append({"name": adapter, "ip": m.group(1)})
    return interfaces


def probe_session(interact_fn, controller_id: str, session_id: str,
                  platform_hint: str = "unknown") -> dict:
    """Send OS profiling commands via interact_fn (interact_session).
    Returns a structured profile: os, privilege, user, interfaces, raw_output.
    Never modifies the target — read-only commands only.
    """
    cmd_key = platform_hint if platform_hint in _OS_COMMANDS else "unknown"
    cmd, _ = _OS_COMMANDS[cmd_key]
    try:
        result = interact_fn(controller_id, session_id, cmd)
        output = result.get("output", "")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "os": "unknown", "privilege": "unknown",
                "user": "unknown", "interfaces": [], "raw_output": ""}

    platform, confidence = _detect_os_from_output(output)
    privilege = _detect_privilege(output, platform)
    user = _detect_user(output, platform)
    interfaces = _extract_interfaces(output, platform)

    return {
        "ok": True,
        "os": platform,
        "os_confidence": confidence,
        "privilege": privilege,
        "user": user,
        "interfaces": interfaces,
        "raw_output": output[-4000:],
        "controller_id": controller_id,
        "session_id": session_id,
        "probed_at": datetime.now(timezone.utc).isoformat(),
    }


def create_demo_account(interact_fn, controller_id: str, session_id: str,
                        platform: str, privilege: str, dry_run: bool = False) -> dict:
    """Create a clearly-identified temporary ASEP demo account.
    Conditions enforced here (not assumed from caller):
      - platform must be 'linux' or 'windows' (not 'unknown' or 'darwin')
      - privilege must indicate administrative capability
      - dry_run=True returns the command that WOULD be executed without running it
    Returns a result dict; never raises (caller logs the result as evidence).
    """
    if platform not in ("linux", "windows"):
        return {"ok": False, "reason": f"OS '{platform}' is not supported for demo account creation. "
                "Only linux and windows are supported. Do not guess the OS."}

    priv_ok = {
        "linux": privilege in ("root",),
        "windows": privilege in ("administrator",),
    }.get(platform, False)
    if not priv_ok:
        return {"ok": False, "reason": f"Privilege '{privilege}' is insufficient for account creation on {platform}. "
                f"Required: {'root' if platform == 'linux' else 'administrator'}. "
                "Do not attempt account creation without confirmed privilege."}

    ts = int(time.time())
    username = f"asep_demo_{ts}"
    # Temporary password: random 12-char hex — not stored outside this call,
    # printed in the result for the operator to record if they need to log in.
    import secrets
    pw = secrets.token_hex(6)

    create_cmd = _DEMO_CREATE[platform].format(user=username, pw=pw)
    validate_cmd = _DEMO_VALIDATE[platform].format(user=username)

    if dry_run:
        return {"ok": True, "dry_run": True, "username": username,
                "create_command": create_cmd, "validate_command": validate_cmd,
                "platform": platform, "privilege": privilege}

    try:
        create_result = interact_fn(controller_id, session_id, create_cmd)
        create_output = create_result.get("output", "")
    except Exception as exc:
        return {"ok": False, "reason": f"Failed to send create command: {exc}", "username": username}

    try:
        val_result = interact_fn(controller_id, session_id, validate_cmd)
        val_output = val_result.get("output", "")
    except Exception as exc:
        val_output = f"Validation command failed: {exc}"

    # Determine whether the account actually exists now.
    created = False
    if platform == "linux":
        created = bool(re.search(rf"\buid=\d+\({re.escape(username)}\)", val_output))
    elif platform == "windows":
        created = username.lower() in val_output.lower() and "the command completed" in val_output.lower()

    return {
        "ok": created,
        "username": username,
        "platform": platform,
        "privilege": privilege,
        "controller_id": controller_id,
        "session_id": session_id,
        "create_output": create_output[-2000:],
        "validation_output": val_output[-2000:],
        "created": created,
        "status": "DEMO_ACCOUNT_CREATED" if created else "DEMO_ACCOUNT_CREATION_FAILED",
        "cleanup_state": "PENDING_OPERATOR_CONFIRMATION",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "note": "This is a temporary ASEP assessment artifact. "
                "Cleanup requires EXPLICIT OPERATOR ACTION via the ASEP GUI — "
                "ASEP will NEVER automatically delete this account.",
    }


def run_demo_cleanup(interact_fn, controller_id: str, session_id: str,
                     platform: str, username: str) -> dict:
    """Execute cleanup of a demo account.
    This is ONLY called by the explicit operator-confirmed cleanup endpoint.
    Never called automatically, never called on session loss, never called
    on ASEP restart, never called on assessment completion (Stage 2 Section 22).
    """
    if platform not in ("linux", "windows"):
        return {"ok": False, "reason": f"Cannot clean up on unsupported platform '{platform}'"}
    if not username.startswith("asep_demo_"):
        return {"ok": False, "reason": "Username does not match ASEP demo account pattern — refusing cleanup to prevent accidental deletion of non-demo accounts"}

    cleanup_cmd = _DEMO_CLEANUP[platform].format(user=username)
    try:
        result = interact_fn(controller_id, session_id, cleanup_cmd)
        output = result.get("output", "")
    except Exception as exc:
        return {"ok": False, "reason": f"Cleanup command failed: {exc}"}

    # Verify the account no longer exists.
    validate_cmd = _DEMO_VALIDATE[platform].format(user=username)
    try:
        val = interact_fn(controller_id, session_id, validate_cmd)
        val_output = val.get("output", "")
    except Exception:
        val_output = ""

    removed = False
    if platform == "linux":
        removed = "no such user" in val_output.lower() or "does not exist" in val_output.lower()
    elif platform == "windows":
        removed = "does not exist" in val_output.lower() or "user not found" in val_output.lower()

    return {
        "ok": removed,
        "username": username,
        "platform": platform,
        "cleanup_output": output[-2000:],
        "validation_output": val_output[-2000:],
        "state": "CLEANUP_VERIFIED" if removed else "CLEANUP_FAILED",
        "cleaned_at": datetime.now(timezone.utc).isoformat(),
    }
