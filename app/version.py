"""ASEP release version, sourced from the repository VERSION file."""
from pathlib import Path

VERSION_FILE = Path(__file__).resolve().parents[1] / "VERSION"
VERSION = VERSION_FILE.read_text(encoding="utf-8").strip()

if not VERSION:
    raise RuntimeError(f"ASEP VERSION file is empty: {VERSION_FILE}")
