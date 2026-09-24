# ASEP Development Rules

## Project Identity

ASEP is an adaptive security assessment and exploitation-capable
security agent.

## Development Rules

1. Follow the approved ASEP Main Plan strictly.
2. Never skip or silently change an approved phase.
3. Verify the current project state before making architectural changes.
4. Preserve completed phases unless a change is explicitly required.
5. Evidence over assumption.
6. Exploit candidate does not mean confirmed vulnerability.
7. Preserve scope and authorization boundaries.
8. Execution must remain controlled through ExecutionController.
9. Do not bypass CHECK → RUN validation.
10. AgentController is responsible for reasoning and action selection.
11. Replanner must learn from failed or invalid candidates.
12. When a path is blocked, analyze the blocker and seek alternative
    approaches that remain within authorized scope.
13. Do not create duplicate subsystems when an existing subsystem
    is sufficient.
14. Run the required test suite before declaring a phase complete.
15. Report changed files, tests, baseline, and remaining gaps.

## Current Development State

Current Main Plan Phase: 1.5

Previous Phase:
1.4 — Engagement Execution Envelope — COMPLETE

Current Phase:
1.5 — Exploit Candidate Correlation and Autonomous Action Integration

Current baseline:
268/268 tests passing

## Important Architecture

Mission State
World State
AgentController
Replanner
ExecutionController
Skill Engine
Evidence
Attack Graph

Execution boundary:
AgentController → proposes
ExecutionController → executes

Never treat exploit candidate/module matching as proof
of vulnerability.
