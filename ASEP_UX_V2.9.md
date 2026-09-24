# ASEP v2.9 UX

## Product identity

ASEP is a Universal Security Intelligence Platform. Tools are executors selected by the capability router; they are not the primary information architecture.

## Pipeline

Understand -> Discover -> Analyze -> Validate -> Exploit -> Post-Exploit -> Achieve

The pipeline is navigational, not a forced linear wizard. Re-planning may move the operation back to discovery or analysis.

## Core objects

Mission -> Target -> Evidence -> Finding -> Attack Path -> Recommendation -> Session -> Report

## Evidence lifecycle

OBSERVED -> INDICATOR -> HYPOTHESIS -> VALIDATING -> CONFIRMED -> EXPLOITABLE

The UX never upgrades a hypothesis to confirmed merely because a tool matched a module.

## Navigation

- Operations: Dashboard, Missions, Targets, Network Map
- Intelligence: Recon & OSINT, Attack Surface, Intelligence, Attack Paths, Deception
- Security: Web/API, Network, Identity/AD, Cloud, Wireless, Linux, Windows
- Research: Vulnerability Research, Reverse Engineering, Malware Analysis
- Execution: Validation, Exploitation, Sessions, Post-Exploitation
- Evidence: Findings, Evidence, Timeline, Reports
- Platform: Skills, Self-Healing, Self-Modifying, Settings

## v2.9 API

The read-only UX aggregation layer is exposed below `/api/v2/` and does not replace the existing execution APIs.
