# ASEP All Skills v1.0 — 75 Skills

This package contains the complete ASEP skill library represented by the current
75-skill design, including Skill #75 Broad Exploit Discovery Intelligence.

## Two supported deployment paths

### A. Claude Project
Upload this ZIP to the Claude Project knowledge/files area. Claude can use the
Markdown skill definitions and registry as project context.

### B. ASEP GUI
Use ASEP GUI -> LLM -> Skills -> Upload Skill when the Dynamic Skill Upload /
Hot-Load feature is available. The intended lifecycle is:

UPLOAD -> VALIDATE -> SHA256 -> SAVE -> REGISTER -> HOT-LOAD -> SELF-TEST -> ACTIVE

Existing skills are additive and must not be silently removed.

## Important
Markdown skills are instructions/data for the intelligence layer. They must never
be treated as executable source code. The ASEP Core remains authoritative for
scope, authorization, policy, CHECK/RUN, approval, execution, and audit.

The package contains the complete 1-75 library as individual .md files so that
skills can also be uploaded one at a time through the GUI.
