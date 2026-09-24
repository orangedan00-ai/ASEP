from pathlib import Path
import os
import re
import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return value.strip().lower() in {"1", "true", "yes", "on"}

def persist_env_var(root, key, value):
    """Update or add one KEY=value line in .env, leaving every other line
    (comments, other keys, ordering) untouched. Used for settings the UI
    lets the operator change live (e.g. ASEP_LLM_MODE) so the choice
    survives a restart, without risking the rest of .env (API keys
    included) on a naive full rewrite.
    """
    env_path = Path(root) / ".env"
    line_re = re.compile(rf"^{re.escape(key)}=.*$")
    new_line = f"{key}={value}"
    if not env_path.exists():
        env_path.write_text(new_line + "\n", encoding="utf-8")
        return
    lines = env_path.read_text(encoding="utf-8").splitlines()
    found = False
    for i, line in enumerate(lines):
        if line_re.match(line):
            lines[i] = new_line
            found = True
            break
    if not found:
        lines.append(new_line)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def load_config():
    scope_path = ROOT / "config" / "scope.yaml"
    with open(scope_path, "r", encoding="utf-8") as f:
        scope = yaml.safe_load(f) or {}

    return {
        "root": ROOT,
        "host": os.getenv("ASEP_HOST", "127.0.0.1"),
        "port": int(os.getenv("ASEP_PORT", "8000")),
        "debug": _env_bool("ASEP_DEBUG", False),
        "scope": scope,
        "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
        "cloud_model": os.getenv("ASEP_CLOUD_MODEL", "gpt-5.6-luna"),
        "local_enabled": os.getenv("ASEP_LOCAL_ENABLED", "true").lower() == "true",
        "ollama_url": os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
        "local_model": os.getenv("ASEP_LOCAL_MODEL", "qwen3:0.6b"),
        "local_num_ctx": int(os.getenv("ASEP_LOCAL_NUM_CTX", "2048")),
        "local_num_predict": int(os.getenv("ASEP_LOCAL_NUM_PREDICT", "256")),
        "local_num_threads": int(os.getenv("ASEP_LOCAL_NUM_THREADS", "2")),
        "intelligence_context_chars": int(os.getenv("ASEP_INTELLIGENCE_CONTEXT_CHARS", "30000")),
        "llm_mode": os.getenv("ASEP_LLM_MODE", "auto"),
        "claude_code_enabled": _env_bool("ASEP_CLAUDE_CODE_ENABLED", False),
        "claude_code_binary": os.getenv("ASEP_CLAUDE_CODE_BINARY", "claude"),
        "claude_code_timeout": int(os.getenv("ASEP_CLAUDE_CODE_TIMEOUT", "120")),
        "claude_code_max_turns": int(os.getenv("ASEP_CLAUDE_CODE_MAX_TURNS", "4")),
        # Stage 2: Internet-aware LLM routing
        "internet_check_url": os.getenv("ASEP_INTERNET_CHECK_URL", "https://dns.google"),
        "internet_check_interval": int(os.getenv("ASEP_INTERNET_CHECK_INTERVAL", "30")),
        "internet_check_timeout": int(os.getenv("ASEP_INTERNET_CHECK_TIMEOUT", "5")),
        "llm_health_check_interval": int(os.getenv("ASEP_LLM_HEALTH_INTERVAL", "60")),
        # Stage 2: Deep scan concurrency (max parallel host scans)
        "deep_scan_concurrency": int(os.getenv("ASEP_DEEP_SCAN_CONCURRENCY", "3")),
        "deep_scan_host_timeout": int(os.getenv("ASEP_DEEP_SCAN_HOST_TIMEOUT", "480")),
        "shell_enabled": os.getenv("ASEP_SHELL_ENABLED", "false").lower() == "true",
        "shell_timeout": int(os.getenv("ASEP_SHELL_TIMEOUT", "120")),
        "shell_cwd": os.getenv("ASEP_SHELL_CWD", ""),
        "root_approval_required": _env_bool("ASEP_ROOT_APPROVAL_REQUIRED", True),
        "tool_timeout": int(os.getenv("ASEP_TOOL_TIMEOUT", "300")),
        "internet_research_enabled": os.getenv("ASEP_INTERNET_RESEARCH_ENABLED", "true").lower() == "true",
        "auto_chain_enabled": os.getenv("ASEP_AUTO_CHAIN_ENABLED", "true").lower() == "true",
        "auto_deep_scan_enabled": os.getenv("ASEP_AUTO_DEEP_SCAN_ENABLED", "true").lower() == "true",
        "auto_deep_scan_new_hosts": os.getenv("ASEP_AUTO_DEEP_SCAN_NEW_HOSTS", "true").lower() == "true",
        "self_modify_enabled": os.getenv("ASEP_SELF_MODIFY_ENABLED", "false").lower() == "true",
        "self_modify_approval_required": os.getenv("ASEP_SELF_MODIFY_APPROVAL_REQUIRED", "true").lower() == "true",
        "self_modify_max_file_bytes": int(os.getenv("ASEP_SELF_MODIFY_MAX_FILE_BYTES", "500000")),
        "auth_user": os.getenv("ASEP_AUTH_USER", "asep"),
        "auth_password": os.getenv("ASEP_AUTH_PASSWORD", ""),
    }
