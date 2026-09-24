"""ASEP Provider Health Monitor (Stage 2).

Periodically checks:
  - Internet connectivity (lightweight HEAD/TCP probe to a reliable endpoint)
  - Local LLM (Ollama /api/tags)
  - Cloud LLM (OpenAI /models) when API key is present
  - Claude Code CLI (binary presence + cached assumption -- the CLI itself
    never exposes a health endpoint without actually billing a call)

Results are cached for at most `interval` seconds (configurable) so the rest
of ASEP can query health synchronously on every dashboard tick without
triggering expensive repeated network calls.

State values match the Stage 2 spec:
  ONLINE / OFFLINE / AVAILABLE / UNAVAILABLE / DEGRADED / CHECKING / ERROR / WORKING
"""
import shutil
import socket
import threading
import time
import urllib.request


class ProviderHealth:
    """Singleton-like health state; one instance is created in create_app()
    and stored in the app closure so all routes share it.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._state = {
            "internet": "CHECKING",
            "local_llm": "CHECKING",
            "cloud": "CHECKING",
            "claude_code": "CHECKING",
            "active_provider": None,
            "last_check": 0.0,
            "last_internet_check": 0.0,
        }
        self._current_task = ""
        self._current_task_ts = 0.0
        self._thread = None
        self._stop_event = threading.Event()

    def start(self):
        """Start the background health-check loop."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="asep-provider-health")
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _loop(self):
        # Immediate first check, then on interval.
        self._run_checks()
        while not self._stop_event.wait(timeout=self.cfg.get("llm_health_check_interval", 60)):
            self._run_checks()

    def _check_internet(self):
        url = self.cfg.get("internet_check_url") or "https://dns.google"
        timeout = self.cfg.get("internet_check_timeout", 5)
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout):
                return "ONLINE"
        except Exception:
            # Fallback: TCP-only probe to 8.8.8.8:53 — never a DNS query,
            # just a TCP handshake, so it works behind strict HTTP proxies too.
            try:
                with socket.create_connection(("8.8.8.8", 53), timeout=timeout):
                    return "ONLINE"
            except Exception:
                return "OFFLINE"

    def _check_local_llm(self):
        if not self.cfg.get("local_enabled"):
            return "UNAVAILABLE"
        base = (self.cfg.get("ollama_url") or "http://127.0.0.1:11434").rstrip("/")
        try:
            req = urllib.request.Request(f"{base}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=4) as r:
                return "AVAILABLE" if r.status == 200 else "DEGRADED"
        except Exception:
            return "UNAVAILABLE"

    def _check_cloud(self):
        if not self.cfg.get("openai_api_key"):
            return "UNAVAILABLE"
        internet = self._state.get("internet", "CHECKING")
        if internet == "OFFLINE":
            return "OFFLINE"
        # Probe OpenAI /models — lightweight, no billing.
        try:
            req = urllib.request.Request(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {self.cfg['openai_api_key']}"},
            )
            with urllib.request.urlopen(req, timeout=6) as r:
                return "AVAILABLE" if r.status == 200 else "DEGRADED"
        except Exception:
            return "UNAVAILABLE"

    def _check_claude_code(self):
        binary = self.cfg.get("claude_code_binary") or "claude"
        if not self.cfg.get("claude_code_enabled"):
            return "UNAVAILABLE"
        if not shutil.which(binary):
            return "UNAVAILABLE"
        # We can't probe Claude Code without billing a real call.
        # Presence + internet = AVAILABLE (assumed). Absence of internet = OFFLINE.
        internet = self._state.get("internet", "CHECKING")
        if internet == "OFFLINE":
            return "OFFLINE"
        return "AVAILABLE"

    def _resolve_active(self, states):
        """Determine the best available provider using the same priority
        as LLMRouter.mode() so the two stay consistent.
        """
        mode = self.cfg.get("llm_mode", "auto")
        if mode == "cloud" and states["cloud"] in ("AVAILABLE", "WORKING"):
            return "cloud"
        if mode == "local" and states["local_llm"] in ("AVAILABLE", "WORKING"):
            return "local"
        if mode == "claude_code" and states["claude_code"] in ("AVAILABLE", "WORKING"):
            return "claude_code"
        # auto priority: cloud → claude_code → local
        for provider, key in [("cloud", "cloud"), ("claude_code", "claude_code"), ("local", "local_llm")]:
            if states.get(key) in ("AVAILABLE", "WORKING"):
                return provider
        return "none"

    def _run_checks(self):
        internet = self._check_internet()
        local = self._check_local_llm()
        cloud = self._check_cloud()
        cc = self._check_claude_code()
        states = {"internet": internet, "local_llm": local, "cloud": cloud, "claude_code": cc}
        active = self._resolve_active(states)
        now = time.time()
        with self._lock:
            self._state.update({**states, "active_provider": active, "last_check": now})

    def snapshot(self):
        """Return a shallow copy of the current health state (thread-safe)."""
        with self._lock:
            task = self._current_task if (time.time() - self._current_task_ts) < 120 else ""
            return {**self._state, "current_task": task, "last_check_age_s": round(time.time() - self._state["last_check"], 1)}

    def set_working(self, provider, task=""):
        """Called by LLMRouter when a call starts so the dashboard shows WORKING."""
        with self._lock:
            key = "cloud" if provider in ("cloud", "claude_code") else "local_llm"
            self._state[key] = "WORKING"
            self._current_task = task
            self._current_task_ts = time.time()

    def clear_working(self, provider, success=True):
        """Called by LLMRouter when a call finishes."""
        with self._lock:
            key = "cloud" if provider in ("cloud", "claude_code") else "local_llm"
            self._state[key] = "AVAILABLE" if success else "DEGRADED"
            self._current_task = ""
