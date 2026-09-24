#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
ASEP_VERSION="$(cat VERSION 2>/dev/null || echo 'unknown')"

echo "=========================================="
echo "        ASEP v${ASEP_VERSION} INSTALLER"
echo "=========================================="

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "[1/10] Updating package index..."
$SUDO apt-get update

echo "[2/10] Installing system dependencies and ASEP tool registry packages..."
# Keep the install list aligned with app/tool_registry.py. Kali packages
# may expose a different binary name (e.g. httpx-toolkit), which is why the
# registry records both apt_package and binary.
ASEP_TOOL_PACKAGES="arp-scan dnsrecon enum4linux httpx-toolkit iw iproute2 kismet netdiscover netexec nikto nmap nuclei sslscan tshark tcpdump whatweb"
$SUDO apt-get install -y \
  python3 \
  python3-venv \
  python3-pip \
  iproute2 \
  network-manager \
  ca-certificates \
  curl \
  unzip \
  tcpdump \
  metasploit-framework \
  $ASEP_TOOL_PACKAGES

echo "[3/10] Creating Python virtual environment..."
python3 -m venv .venv

echo "[4/10] Installing Python packages..."
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "[5/10] Creating runtime directories..."
mkdir -p data logs evidence

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

echo "[6/10] Setting up Local LLM (Ollama)..."
if command -v ollama >/dev/null 2>&1; then
  echo "Ollama: already installed ($(ollama --version 2>/dev/null || echo 'version unknown'))"
else
  echo "Installing Ollama (official installer: https://ollama.com/install.sh)..."
  curl -fsSL https://ollama.com/install.sh | sh || echo "WARNING: Ollama install failed — you can retry later or install manually."
fi

LOCAL_ENABLED="true"
LOCAL_MODEL="qwen3:0.6b"
if [[ -f .env ]]; then
  grep -Eq '^ASEP_LOCAL_ENABLED=(0|false|no|off)$' .env && LOCAL_ENABLED="false"
  CUSTOM_MODEL="$(grep -E '^ASEP_LOCAL_MODEL=' .env | tail -n1 | cut -d= -f2-)"
  [[ -n "${CUSTOM_MODEL}" ]] && LOCAL_MODEL="${CUSTOM_MODEL}"
fi

if command -v ollama >/dev/null 2>&1; then
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ollama.service'; then
    $SUDO systemctl enable --now ollama 2>/dev/null || true
  fi
  if [[ "${LOCAL_ENABLED}" == "true" ]]; then
    echo "Pulling local model: ${LOCAL_MODEL} (this may take a while on first run)..."
    ollama pull "${LOCAL_MODEL}" || echo "WARNING: Could not pull ${LOCAL_MODEL} now — run 'ollama pull ${LOCAL_MODEL}' manually once you have network access."
  else
    echo "ASEP_LOCAL_ENABLED=false in .env — skipping model pull. Set it to true and re-run 'ollama pull ${LOCAL_MODEL}' to enable later."
  fi
else
  echo "WARNING: Ollama is still not available — Local LLM will be unusable until it's installed."
fi

echo "[7/10] Setting up Claude Code CLI (hybrid reasoning backend)..."
if command -v claude >/dev/null 2>&1; then
  echo "Claude Code CLI: already installed ($(claude --version 2>/dev/null || echo 'version unknown'))"
else
  echo "Installing Claude Code CLI (official installer: https://claude.ai/install.sh)..."
  curl -fsSL https://claude.ai/install.sh | bash || echo "WARNING: Claude Code install failed — you can retry later: curl -fsSL https://claude.ai/install.sh | bash"
fi
echo "NOTE: Claude Code requires an interactive login (OAuth) that this installer cannot script."
echo "      After install, run 'claude' once by hand and log in with your subscription, then set"
echo "      ASEP_CLAUDE_CODE_ENABLED=true in .env to let ASEP use it as a reasoning backend."

echo "[8/10] Checking sudo..."
if command -v sudo >/dev/null 2>&1; then
  echo "sudo: OK"
else
  echo "ERROR: sudo is not installed."
  exit 1
fi

echo "[9/10] Installing systemd service..."
chmod +x asep install.sh

# Install ASEP as a systemd service, but run it as the installing user (never root).
if command -v systemctl >/dev/null 2>&1; then
  ASEP_USER="${SUDO_USER:-${USER}}"
  ASEP_GROUP="$(id -gn "${ASEP_USER}")"
  SERVICE_FILE="/etc/systemd/system/asep.service"
  SELF_MODIFY_ENABLED="false"
  if [[ -f .env ]] && grep -Eq '^ASEP_SELF_MODIFY_ENABLED=(1|true|yes|on)$' .env; then
    SELF_MODIFY_ENABLED="true"
  fi
  # ProtectHome=read-only is kept for the normal hardened service. If the
  # project lives under /home and self-modifying is explicitly enabled, that
  # protection would prevent the checkpoint/patch lifecycle from writing the
  # ASEP source tree. In that opt-in mode only, disable ProtectHome;
  # ProtectSystem plus ReadWritePaths still constrain the writable areas.
  PROTECT_HOME="read-only"
  if [[ "${SELF_MODIFY_ENABLED}" == "true" && "${ROOT}" == /home/* ]]; then
    PROTECT_HOME="false"
    echo "WARNING: self-modifying mode is enabled under /home; ProtectHome is disabled for the ASEP service so checkpoint/patch writes can succeed."
  fi
  sed \
    -e "s|__ASEP_USER__|${ASEP_USER}|g" \
    -e "s|__ASEP_GROUP__|${ASEP_GROUP}|g" \
    -e "s|__ASEP_ROOT__|${ROOT}|g" \
    -e "s|__ASEP_PROTECT_HOME__|${PROTECT_HOME}|g" \
    asep.service.template | $SUDO tee "${SERVICE_FILE}" >/dev/null
  $SUDO chmod 644 "${SERVICE_FILE}"
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable asep.service
  echo "systemd: enabled (ASEP starts automatically at boot)"
else
  echo "WARNING: systemd is not available; ASEP auto-start was not configured."
fi

echo "[10/10] Evidence tool engine ready."
echo "Tool inventory is detected at runtime; install additional Kali tool packages as needed."
echo "Tool registry packages were installed automatically where available."
echo "Installation finished."

echo
echo "=========================================="
echo "ASEP v${ASEP_VERSION} installation complete."
echo "=========================================="
echo
echo "Local LLM (Ollama) — installed and model pulled automatically above."
echo "  Model in use: ${LOCAL_MODEL}"
echo "  ASEP_LOCAL_ENABLED=true"
echo "  ASEP_LOCAL_NUM_CTX=2048"
echo "  ASEP_LOCAL_NUM_PREDICT=256"
echo
echo "Claude Code (hybrid reasoning backend, your own subscription):"
if command -v claude >/dev/null 2>&1; then
  echo "  CLI installed. Still required (cannot be scripted): run 'claude' once and log in."
else
  echo "  Not installed. Run: curl -fsSL https://claude.ai/install.sh | bash"
fi
echo "  Then in .env: ASEP_CLAUDE_CODE_ENABLED=true"
echo
echo "Configure:"
echo "  nano .env"
echo
echo "Enable local shell:"
echo "  ASEP_SHELL_ENABLED=true"
echo
echo "Configure scope:"
echo "  nano config/scope.yaml"
echo
echo "Start manually:"
echo "  ./asep"
echo
echo "Service:"
echo "  sudo systemctl start asep"
echo "  sudo systemctl status asep"
echo "  sudo systemctl restart asep"
echo "  sudo systemctl stop asep"
echo "  journalctl -u asep -f"
echo
echo "Open:"
echo "  http://127.0.0.1:8000"
echo
echo "Root commands require explicit approval."
echo "The sudo password is entered by you and is not sent to ASEP/LLM."
