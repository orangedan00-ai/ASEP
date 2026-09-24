# Metasploit Universal Session/Exploitation Skill

## Purpose
Treat Metasploit as a platform-agnostic exploitation and session framework.
Do not hard-code Windows as the prerequisite.

## Capability flow
FINGERPRINT → MODULE MATCH → PREREQUISITE/EVIDENCE REVIEW → CHECK → APPROVED ACTION → SESSION/OTHER OUTCOME → SESSION INTELLIGENCE

## Supported reasoning
- correlate OS/platform, architecture, service, version and existing evidence
- identify compatible Metasploit modules
- determine whether CHECK is supported
- identify expected outcomes (session or non-session)
- identify compatible session types where applicable
- feed established sessions into Post-Session Intelligence
- update the Attack Graph with new evidence

## Important behavior
A module match is not a vulnerability confirmation.
A CHECK result is not a license to execute unrelated actions.
Consequential actions remain subject to scope, policy and explicit operator approval.
