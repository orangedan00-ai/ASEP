import os
import subprocess
from pathlib import Path

class ShellError(Exception):
    pass

def run_shell(cfg, command):
    if not cfg["shell_enabled"]:
        raise ShellError("Local shell executor disabled. Set ASEP_SHELL_ENABLED=true in .env.")

    command = (command or "").strip()
    if not command:
        raise ShellError("Command kosong.")

    cwd = cfg["shell_cwd"] or str(cfg["root"])
    Path(cwd).mkdir(parents=True, exist_ok=True)

    # Execute as the same OS user that launched ASEP.
    # No shell privilege escalation is performed by ASEP itself.
    try:
        proc = subprocess.run(
            ["/bin/bash", "-lc", command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=cfg["shell_timeout"],
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as e:
        raise ShellError(f"Command timeout setelah {cfg['shell_timeout']} detik.") from e

    return {
        "command": command,
        "cwd": cwd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
