
"""ASEP adaptive re-planning engine.

Generates and ranks alternative next actions from objective, evidence and
failed/blocked paths. It plans; it does not execute actions.
"""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class PlanState:
    objective: str
    evidence: List[Dict] = field(default_factory=list)
    failed_actions: List[Dict] = field(default_factory=list)
    blocked_paths: List[Dict] = field(default_factory=list)
    available_capabilities: List[str] = field(default_factory=list)


class Replanner:
    def __init__(self, llm=None):
        self.history = []
        self.llm = llm

    def replan(self, state: PlanState) -> Dict:
        candidates = []
        failed_ids = {str(x.get("action_id")) for x in state.failed_actions}

        base = [
            ("COLLECT_MISSING_EVIDENCE", "Collect missing evidence before acting", 0.85, "LOW"),
            ("RECALCULATE_ATTACK_GRAPH", "Recalculate evidence-backed attack paths", 0.90, "LOW"),
            ("VALIDATE_ASSUMPTION", "Validate the assumption that caused the blocked path", 0.88, "LOW"),
            ("TRY_ALTERNATIVE_CAPABILITY", "Use an alternative capability supported by current evidence", 0.75, "MEDIUM"),
            ("PRESERVE_AND_REPORT", "Preserve evidence and document the current boundary", 0.65, "LOW"),
        ]

        for action_id, title, confidence, risk in base:
            if action_id in failed_ids:
                continue
            candidates.append({
                "action_id": action_id,
                "title": title,
                "confidence": confidence,
                "risk": risk,
                "requires_approval": action_id in {
                    "TRY_ALTERNATIVE_CAPABILITY",
                    "VALIDATE_ASSUMPTION",
                },
                "reason": "Generated from current objective/evidence and prior failure state.",
            })

        # Prefer low-risk evidence/graph actions when the current state is uncertain.
        candidates.sort(key=lambda x: (-x["confidence"], x["risk"] != "LOW"))
        result = {
            "objective": state.objective,
            "candidate_actions": candidates,
            "failed_action_count": len(state.failed_actions),
            "blocked_path_count": len(state.blocked_paths),
            "adapted": bool(state.failed_actions or state.blocked_paths),
        }

        # Optional LLM enrichment (Fase 1 hybrid-LLM autonomy). This never
        # replaces the deterministic candidates above -- it's additive
        # reasoning, and any failure here (LLM unavailable, backend error,
        # timeout) must never break replanning itself.
        if self.llm is not None:
            try:
                if self.llm.mode() != "none":
                    context = (
                        f"Objective: {state.objective}\n"
                        f"Evidence: {state.evidence}\n"
                        f"Failed actions: {state.failed_actions}\n"
                        f"Blocked paths: {state.blocked_paths}\n"
                        f"Available capabilities: {state.available_capabilities}\n"
                        f"Deterministic candidates already generated: {[c['action_id'] for c in candidates]}"
                    )
                    reasoning = self.llm.reason_with_skill(
                        context, skill_ids=["adaptive_replanning", "failure_intelligence"]
                    )
                    result["llm_reasoning"] = {
                        "mode": reasoning.get("mode"),
                        "skill_ids": reasoning.get("skill_ids"),
                        "text": reasoning.get("text"),
                    }
            except Exception as exc:
                result["llm_reasoning"] = {"mode": "error", "text": f"LLM reasoning unavailable: {exc}"}

        self.history.append(result)
        return result
