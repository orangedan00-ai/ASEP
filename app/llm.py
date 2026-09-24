import json
import os
import shutil
import subprocess
import requests
from pathlib import Path

SYSTEM_PROMPT = """
You are ASEP, an evidence-driven cybersecurity assessment assistant.

Your reasoning loop is:
DISCOVER -> ANALYZE -> VALIDATE -> RE-CHECK -> VERIFY -> CORRELATE -> REPORT

Treat tool output as evidence, not truth.
Never call an unverified hypothesis a confirmed vulnerability.

When analyzing evidence, separate:
FACT
OBSERVATION
HYPOTHESIS
CONFIRMED
EXPLOITABLE
FALSE POSITIVE
UNKNOWN

Do not expand testing scope automatically.
When evidence is insufficient, explicitly say what remains unverified.

For Nmap output, focus on:
- discovered hosts
- exposed services
- versions
- unusual exposure
- validation ideas
- possible attack-path relationships

Do not invent CVEs or vulnerabilities.
"""

class LLMRouter:
    def __init__(self, cfg):
        self.cfg = cfg

    def mode(self):
        requested = self.cfg["llm_mode"]
        if requested == "cloud":
            return "cloud"
        if requested == "local":
            return "local"
        if requested == "claude_code":
            return "claude_code"
        if self.cfg["openai_api_key"]:
            return "cloud"
        if self.cfg.get("claude_code_enabled") and shutil.which(self.cfg.get("claude_code_binary") or "claude"):
            return "claude_code"
        if self.cfg["local_enabled"]:
            return "local"
        return "none"

    def ask_cloud(self, prompt):
        # OpenAI SDK is an optional runtime dependency. ASEP can run in
        # local/offline mode without importing it at application startup.
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "Cloud LLM dipilih tetapi package 'openai' belum terpasang. "
                "Install dengan: python3 -m pip install openai"
            ) from exc

        client = OpenAI(api_key=self.cfg["openai_api_key"])
        response = client.responses.create(
            model=self.cfg["cloud_model"],
            input=f"{SYSTEM_PROMPT}\n\nUSER/EVIDENCE:\n{prompt}",
        )
        return {"mode": "cloud", "text": response.output_text, "available": True}

    def ask_local(self, prompt, options=None):
        if not self.cfg["local_enabled"]:
            raise RuntimeError("Local LLM disabled.")
        payload = {
            "model": self.cfg["local_model"],
            "prompt": f"{SYSTEM_PROMPT}\n\nUSER/EVIDENCE:\n{prompt}",
            "stream": False,
            "keep_alive": "5m",
            "options": options or {},
        }
        r = requests.post(
            self.cfg["ollama_url"].rstrip("/") + "/api/generate",
            json=payload,
            timeout=300,
        )
        r.raise_for_status()
        return {"mode": "local", "text": r.json().get("response", ""), "available": True}

    def ask_claude_code(self, prompt):
        # Uses the operator's own Claude Code CLI session (Pro/Max subscription
        # login via `claude` interactively, once) -- not the Claude API and not
        # a separate API key. Deliberately does NOT pass --bare: bare mode
        # disables OAuth/subscription auth entirely and requires
        # ANTHROPIC_API_KEY instead, which would defeat the point of reusing
        # an existing subscription. Deliberately does NOT pass --allowedTools:
        # this backend is reasoning-only (same contract as ask_cloud/ask_local)
        # with zero file/bash/tool access. --permission-prompts none is the
        # officially documented way to run unattended without a human present
        # to approve anything; combined with no --allowedTools, every tool
        # attempt is cleanly denied instead of hanging. Runs from an isolated
        # scratch directory (not ASEP's own project root) so it never picks up
        # a stray .claude/settings.json, .mcp.json or CLAUDE.md from this repo.
        # See: docs.claude.com/en/docs/claude-code/headless
        binary = self.cfg.get("claude_code_binary") or "claude"
        resolved = shutil.which(binary)
        if not resolved:
            raise RuntimeError(
                f"Claude Code CLI ('{binary}') tidak ditemukan di PATH. "
                "Install dengan: curl -fsSL https://claude.ai/install.sh | bash "
                "lalu jalankan 'claude' sekali secara interaktif untuk login dengan langganan Anda."
            )

        scratch_dir = self.cfg.get("claude_code_cwd") or str(Path(self.cfg["root"]) / "data" / "llm_cc_scratch")
        os.makedirs(scratch_dir, exist_ok=True)

        timeout = self.cfg.get("claude_code_timeout", 120)
        max_turns = self.cfg.get("claude_code_max_turns", 4)
        full_prompt = f"{SYSTEM_PROMPT}\n\nUSER/EVIDENCE:\n{prompt}"
        cmd = [
            resolved, "-p", full_prompt,
            "--output-format", "json",
            "--permission-prompts", "none",
            "--max-turns", str(max_turns),
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=scratch_dir)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Claude Code tidak merespons dalam {timeout} detik (timeout).") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(f"Claude Code CLI ('{binary}') tidak bisa dijalankan.") from exc

        stdout = (proc.stdout or "").strip()
        if not stdout:
            stderr = (proc.stderr or "").strip()
            hint = f" stderr: {stderr}" if stderr else ""
            raise RuntimeError(
                "Claude Code CLI tidak mengembalikan output." + hint +
                " Kemungkinan penyebab: belum login (jalankan 'claude' sekali secara interaktif), "
                "atau versi CLI terlalu lama untuk --permission-prompts (butuh v2.1.259+; "
                "update dengan: claude update)."
            )

        try:
            payload = json.loads(stdout)
        except ValueError as exc:
            raise RuntimeError(
                "Claude Code CLI mengembalikan output yang tidak bisa di-parse sebagai JSON."
            ) from exc

        return {
            "mode": "claude_code",
            "text": payload.get("result", ""),
            "available": True,
            "session_id": payload.get("session_id"),
            "cost_usd": payload.get("total_cost_usd"),
        }

    def ask(self, prompt, _health=None):
        mode = self.mode()
        if _health:
            _health.set_working(mode, task="LLM reasoning")
        try:
            if mode == "cloud":
                result = self.ask_cloud(prompt)
            elif mode == "local":
                result = self.ask_local(prompt)
            elif mode == "claude_code":
                result = self.ask_claude_code(prompt)
            else:
                result = {
                    "mode": "none",
                    "text": "LLM belum dikonfigurasi. Isi .env untuk Cloud, Local, atau Claude Code.",
                }
        except Exception:
            if _health:
                _health.clear_working(mode, success=False)
            raise
        if _health:
            _health.clear_working(mode, success=True)
        return result

    def reason_with_skill(self, context, skill_ids=None, limit=3, _health=None):
        """Reason about `context` through one or more skills from the
        persistent Skill Registry (app/skill_registry.py — Tahap 1 of the
        75-skill upgrade), via whichever backend ask() resolves to.
        skill_ids=None auto-selects by keyword match against context. Returns
        ask()'s normal {mode, text, ...} shape plus the skill_ids actually
        used, so callers can show which lens produced the reasoning.
        """
        from .skill_registry import select_skills, build_skill_prompt
        ids = skill_ids or select_skills(self.cfg, context, limit=limit)
        prompt = build_skill_prompt(self.cfg, ids, context)
        result = self.ask(prompt, _health=_health)
        return {**result, "skill_ids": ids}
