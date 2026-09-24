# ASEP Current State

## Current Main Plan Phase

Phase 1.5

## Previous Completed Phase

Phase 1.4 — Engagement Execution Envelope

## Baseline

268/268 tests passing

## Current Objective

Connect:

exploit_candidates
        ↓
AgentController
        ↓
agent_actions
        ↓
ExecutionController
        ↓
CHECK
        ↓
RUN
        ↓
Session
        ↓
Evidence
        ↓
World State
        ↓
Replanner

## Current Gap

exploit_candidates already exists but concrete exploit
module selection is not yet fully propagated into
AgentController agent actions.

## Rules

Do not unnecessarily modify Phase 1.4 execution/envelope logic.

Do not bypass scope.

Do not bypass CHECK → RUN.

Candidate != vulnerability.

Keep provenance and evidence.
