# ASEP v2.5 — Post-Session Intelligence

After an authorized Metasploit session is established, ASEP treats the session
as new evidence rather than as an automatic command-execution trigger.

Flow:

SESSION → PROFILE → EVIDENCE → ATTACK GRAPH UPDATE → NEXT-ACTION OPTIONS

ASEP can recommend:
- security-context profiling
- network-path analysis
- domain/identity relationship analysis
- attack-graph recalculation
- evidence preservation

Each recommendation includes:
- reason
- supporting evidence
- confidence
- risk
- approval requirement

Consequential actions require explicit operator selection/approval. The engine
does not automatically perform unrestricted post-exploitation.
