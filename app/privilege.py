import os
import pty
import select
import subprocess
import time

class PrivilegeError(Exception):
    pass

def current_user():
    return {
        "uid": os.getuid(),
        "user": os.getenv("USER") or os.getenv("LOGNAME") or "unknown",
        "is_root": os.getuid() == 0,
    }

def run_with_sudo(cfg, command, approved=False):
    """
    Execute a command through sudo using a pseudo-terminal so sudo can
    prompt the human operator for their password.

    The password is typed directly into the PTY by the user. It is never
    accepted as an API parameter and never passed to the LLM.
    """
    if not cfg["shell_enabled"]:
        raise PrivilegeError("Local shell executor is disabled.")

    if cfg.get("root_approval_required", True) and not approved:
        raise PrivilegeError("Explicit user approval is required for root execution.")

    command = (command or "").strip()
    if not command:
        raise PrivilegeError("Command kosong.")

    cwd = cfg["shell_cwd"] or str(cfg["root"])

    # `sudo -v` first: password is entered by the user in the terminal/PTY.
    # Then run the requested command without accepting a password from the API.
    full = f"sudo -v && sudo -- {command}"

    pid, fd = pty.fork()

    if pid == 0:
        os.chdir(cwd)
        os.execv("/bin/bash", ["bash", "-lc", full])

    output = []
    start = time.time()

    while True:
        if time.time() - start > cfg["shell_timeout"]:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
            raise PrivilegeError("Root command timeout.")

        r, _, _ = select.select([fd], [], [], 0.25)
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if chunk:
                text = chunk.decode(errors="replace")
                output.append(text)
                # PTY output is intentionally returned to the local UI.
                print(text, end="", flush=True)
            else:
                break

        try:
            finished_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break

        if finished_pid == pid:
            return {
                "command": command,
                "cwd": cwd,
                "returncode": os.waitstatus_to_exitcode(status),
                "stdout": "".join(output),
            }

    _, status = os.waitpid(pid, 0)
    return {
        "command": command,
        "cwd": cwd,
        "returncode": os.waitstatus_to_exitcode(status),
        "stdout": "".join(output),
    }
