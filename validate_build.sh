#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ -n "${PYTHON:-}" ]; then
  PYTHON="$PYTHON"
elif [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
else
  PYTHON="python3"
fi
AUTO_INSTALL="${ASEP_AUTO_INSTALL:-0}"
REQUIRE_RUNTIME="${ASEP_REQUIRE_RUNTIME:-0}"

echo "=========================================="
VERSION="$(cat "$ROOT/VERSION")"
echo "       ASEP v${VERSION} BUILD VALIDATION"
echo "=========================================="

echo "[1/8] Python syntax..."
"$PYTHON" -m py_compile app/*.py tests/*.py

echo "[2/8] JavaScript syntax..."
if command -v node >/dev/null 2>&1 && [ -f static/app.js ]; then
  node --check static/app.js
else
  echo "Node.js unavailable; JavaScript syntax check skipped."
fi

echo "[3/8] Dependency check..."
echo "Using Python: $PYTHON"
if "$PYTHON" -c 'import flask, yaml, dotenv, requests, psutil' >/dev/null 2>&1; then
  echo "Python runtime dependencies: OK"
else
  echo "Flask or another runtime dependency is missing."
  if [ "$AUTO_INSTALL" = "1" ]; then
    echo "Attempting dependency installation..."
    "$PYTHON" -m pip install -r requirements.txt
    "$PYTHON" -c 'import flask, yaml, dotenv, requests, psutil'
  else
    echo "Core tests are still runnable; OpenAI SDK is optional unless Cloud LLM is used."
    echo "For full runtime validation:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/python -m pip install -r requirements.txt"
    echo "  ASEP_REQUIRE_RUNTIME=1 ./validate_build.sh"
  fi
fi

echo "[4/8] Unit/integration engine tests..."
"$PYTHON" -m unittest discover -s tests -p 'test_*.py'

echo "[5/8] Route contract..."
"$PYTHON" -m unittest tests.test_route_contract

echo "[6/8] Runtime smoke..."
if "$PYTHON" -c 'import flask' >/dev/null 2>&1; then
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" tests/runtime_smoke.py
else
  echo "RUNTIME_SMOKE: SKIPPED (Flask not installed in this validation environment)."
  if [ "$REQUIRE_RUNTIME" = "1" ]; then
    echo "ERROR: Runtime validation was required but Flask is missing."
    exit 2
  fi
fi

echo "[7/8] UX contract..."
"$PYTHON" -m unittest tests.test_ux_contract

echo "[8/8] Package hygiene..."
if find . -type d -name '__pycache__' -print -quit | grep -q .; then
  echo "Note: __pycache__ exists; release packaging should exclude it."
fi

echo "Environment discovery, UX API/runtime contracts included."
echo "ASEP v${VERSION} validation: PASS"
