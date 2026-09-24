# ASEP v2.6 — Metasploit Universal Session/Exploitation Skill

ASEP now treats Metasploit as a universal capability rather than a Windows-only
feature.

Example reasoning:

> Target ini bukan Windows, tetapi fingerprint dan service-nya cocok dengan
> capability Metasploit X. Module tersebut mendukung check dan berpotensi
> menghasilkan session Y. Mari validasi evidence terlebih dahulu.

ASEP should:
1. fingerprint platform/service/architecture/version
2. correlate evidence
3. identify compatible Metasploit module candidates
4. determine CHECK support and expected outcome
5. determine possible session type when applicable
6. validate prerequisites
7. enforce scope and explicit approval gates
8. execute only through the existing controlled orchestrator
9. treat any resulting session as new evidence
10. pass the session to Post-Session Intelligence and Attack Graph

A module match is never treated as proof of vulnerability.
Not every Metasploit module produces a shell/session.
