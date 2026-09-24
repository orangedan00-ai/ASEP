
"""Controlled ASEP self-modifying source engine.

Changes are restricted to the ASEP project root, checkpointed before write,
validated with deterministic Python tests/compile checks, and rolled back on
failure. It never writes outside the configured root.
"""
from pathlib import Path
from datetime import datetime, timezone
import difflib
import json
import shutil
import subprocess
import sys
import tempfile


class SelfModifyError(Exception):
    pass


class SelfModifier:
    def __init__(self, root, max_file_bytes=500000):
        self.root = Path(root).resolve()
        self.max_file_bytes = int(max_file_bytes)

    def _safe_path(self, rel):
        p = (self.root / str(rel)).resolve()
        if p != self.root and self.root not in p.parents:
            raise SelfModifyError(f"Path outside ASEP root: {rel}")
        return p

    def preview(self, changes):
        diffs = []
        for rel, new_text in (changes or {}).items():
            p = self._safe_path(rel)
            old = p.read_text(encoding="utf-8") if p.exists() else ""
            if len(str(new_text).encode("utf-8")) > self.max_file_bytes:
                raise SelfModifyError(f"File too large: {rel}")
            diffs.append({
                "path": str(rel),
                "changed": old != str(new_text),
                "diff": "".join(difflib.unified_diff(
                    old.splitlines(True),
                    str(new_text).splitlines(True),
                    fromfile=str(rel),
                    tofile=str(rel),
                )),
            })
        return {"files": diffs, "file_count": len(diffs)}

    def apply_and_validate(self, changes, run_tests=True):
        preview = self.preview(changes)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = self.root / "data" / "self_modify" / stamp
        backup.mkdir(parents=True, exist_ok=True)
        manifest = []

        try:
            for rel, new_text in (changes or {}).items():
                p = self._safe_path(rel)
                if p.exists():
                    dst = backup / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(p, dst)
                    existed = True
                else:
                    existed = False
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(str(new_text), encoding="utf-8")
                manifest.append({"path": rel, "existed": existed})

            py_files = [str(p) for p in self.root.rglob("*.py")
                        if ".venv" not in p.parts and "__pycache__" not in p.parts]
            subprocess.run([sys.executable, "-m", "py_compile", *py_files],
                           cwd=self.root, check=True, capture_output=True, text=True)

            if run_tests:
                result = subprocess.run(
                    [sys.executable, "-m", "unittest", "discover", "-s", str(self.root / "tests")],
                    cwd=self.root, check=True, capture_output=True, text=True,
                )
                test_output = result.stdout[-12000:]
            else:
                test_output = "tests skipped by caller"

            (backup / "manifest.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
            return {
                "ok": True,
                "status": "ACTIVATED",
                "checkpoint": str(backup.relative_to(self.root)),
                "preview": preview,
                "test_output": test_output,
            }

        except Exception as exc:
            # Restore every touched file from the checkpoint.
            for item in manifest:
                p = self._safe_path(item["path"])
                old = backup / item["path"]
                if item["existed"] and old.exists():
                    shutil.copy2(old, p)
                elif not item["existed"] and p.exists():
                    p.unlink()
            return {
                "ok": False,
                "status": "ROLLED_BACK",
                "checkpoint": str(backup.relative_to(self.root)),
                "preview": preview,
                "error": str(exc),
            }
