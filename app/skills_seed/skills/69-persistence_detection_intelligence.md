---
id: persistence_detection_intelligence
name: Persistence Detection Intelligence
version: 1.0
skill_number: 69
category: defense
author: ASEP Project
status: enabled
source: asep_skill_library
tags:
  - asep
  - defense
  - intelligence
---

# Skill 69: Persistence Detection Intelligence

## Purpose
Provide ASEP with structured reasoning for **Persistence Detection Intelligence** within the evidence-driven
security-assessment lifecycle.

## Objective
Use this capability to analyze the current mission state, correlate relevant
evidence, identify uncertainty and prerequisites, and recommend the next
appropriate capability or validation step.

## Inputs
- Current mission objective and state.
- In-scope asset and service inventory.
- Relevant evidence records and provenance.
- Existing findings, hypotheses, sessions, and attack-graph state when applicable.
- Results from other ASEP skills.
- Environment/tool availability when relevant.

## Rules
- Evidence > assumption.
- A discovered condition is not automatically a vulnerability.
- A candidate is not confirmation.
- Missing evidence must remain explicitly missing.
- Conflicting evidence must be preserved and resolved using provenance and recency.
- Do not silently convert hypotheses into facts.
- Do not directly execute commands.
- Do not bypass scope, authorization, policy, approval, or safety gates.
- Prefer the least intrusive action that materially improves information quality.

## ASEP Core Boundary
This skill is an intelligence capability, not an execution authority.
ASEP Core remains authoritative for scope, authorization, policy, CHECK/RUN,
approval, execution, state integrity, and auditability.

Never fabricate evidence. Preserve uncertainty and provenance.
An LLM recommendation is not evidence and is not authorization.

## Operating Method
1. Read the current mission state and objective.
2. Consume only relevant observed evidence.
3. Identify gaps, conflicts, prerequisites, and constraints.
4. Produce structured reasoning and a recommended next step.
5. If an action is proposed, route it through:
   PROPOSE -> SCOPE CHECK -> AUTHORIZATION CHECK -> POLICY CHECK -> CHECK -> APPROVAL -> RUN.
6. Record the evidence and reasoning basis.

## Output Contract
Prefer:
- decision
- objective
- relevant_evidence
- missing_evidence
- assumptions
- prerequisites
- recommended_next_step
- confidence
- status

Confidence describes evidence-supported confidence in the analysis, not guaranteed outcome.

