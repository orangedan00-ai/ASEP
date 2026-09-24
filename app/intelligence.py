import json
import re
import time
from datetime import datetime, timezone

from .llm import LLMRouter

SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*([^\s,;]+)'),
    re.compile(r'(?i)bearer\s+[A-Za-z0-9._~+/=-]+'),
    re.compile(r'(?i)-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----', re.S),
]

SYSTEM_CONTEXT = """ASEP Intelligence Engine.
You are an evidence-driven cybersecurity assessment analyst. Use the supplied internal-network evidence as context.
Do not invent vulnerabilities, CVEs, credentials, or compromise. Separate FACT, OBSERVATION, HYPOTHESIS, CONFIRMED, EXPLOITABLE, FALSE POSITIVE, and UNKNOWN.
Correlate Network Map, Wireless, Nmap/services, Evidence Store, and attack-path candidates. Identify missing validation and alternative validation paths when a hypothesis is blocked.
Do not expand scope. Do not treat reachability as compromise.
"""


def redact_secrets(text: str) -> str:
    out = text or ""
    for pat in SECRET_PATTERNS:
        if pat.pattern.lower().startswith('(?i)-----begin'):
            out = pat.sub('[PRIVATE_KEY_REDACTED]', out)
        elif 'bearer' in pat.pattern.lower():
            out = pat.sub('Bearer [TOKEN_REDACTED]', out)
        else:
            out = pat.sub(lambda m: f"{m.group(1)}=[REDACTED]", out)
    return out


def compact_json(obj, max_chars=18000):
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    raw = redact_secrets(raw)
    if len(raw) <= max_chars:
        return raw
    return raw[:max_chars] + "\n...[context truncated]"


class IntelligenceEngine:
    def __init__(self, cfg, llm: LLMRouter):
        self.cfg = cfg
        self.llm = llm

    def build_context(self, network_map=None, evidence=None, wireless=None, attack_path=None, target=None):
        context = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "network_map": network_map or {},
            "wireless": wireless or {},
            "attack_path": attack_path or {},
            "evidence": evidence or [],
        }
        return redact_secrets(compact_json(context, int(self.cfg.get("intelligence_context_chars", 30000))))

    def local_preprocess(self, context: str):
        """Lightweight local pass. It is intentionally small for old laptops."""
        if not self.cfg.get("local_enabled"):
            return {"available": False, "mode": "disabled", "summary": context[:6000]}
        prompt = (
            SYSTEM_CONTEXT
            + "\nPerform a lightweight preprocessing pass only. Extract entities, services, relationships, anomalies and missing evidence. "
              "Be concise; do not perform deep reasoning.\n\nCONTEXT:\n" + context
        )
        started = time.time()
        try:
            result = self.llm.ask_local(prompt, options={
                "num_ctx": int(self.cfg.get("local_num_ctx", 2048)),
                "num_predict": int(self.cfg.get("local_num_predict", 256)),
                "temperature": 0.1,
                "num_thread": int(self.cfg.get("local_num_threads", 2)),
            })
            result["elapsed_sec"] = round(time.time() - started, 2)
            return result
        except Exception as exc:
            return {"available": False, "mode": "local-error", "error": str(exc), "summary": context[:6000]}

    def analyze(self, context: str, use_cloud=True, use_local=True):
        local = self.local_preprocess(context) if use_local else {"available": False, "mode": "skipped", "summary": context[:6000]}
        enriched = context
        if local.get("text"):
            enriched += "\n\nLOCAL PREPROCESSING SUMMARY:\n" + redact_secrets(local["text"])

        cloud = None
        if use_cloud and self.cfg.get("openai_api_key"):
            prompt = (
                SYSTEM_CONTEXT
                + "\nPerform the main intelligence analysis. Correlate all evidence. Produce: Executive Summary; Asset/Service Correlation; "
                  "Attack-Path Candidates; Validation Gaps; Alternative Validation Paths; False-Positive Risks; Recommended Next Checks. "
                  "Do not execute commands and do not claim access unless the evidence explicitly confirms it.\n\nCONTEXT:\n"
                + enriched
            )
            cloud = self.llm.ask_cloud(prompt)
        elif use_cloud:
            cloud = {"mode": "cloud-unavailable", "text": "Cloud LLM is not configured (OPENAI_API_KEY missing)."}

        return {
            "ok": True,
            "local": local,
            "cloud": cloud,
            "mode": "hybrid" if cloud and local.get("available") else ("cloud" if cloud else "local"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
