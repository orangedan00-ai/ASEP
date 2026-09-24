## v2.9.33 — Stage 2 Batch 1: Parallel Deep Scan + Internet-Aware LLM + Provider Health
Source inspection (Phase 1) confirmed the implementation gaps before any code was changed. Three concrete problems found and fixed:

**1. Deep scan: serial → parallel, and the timeout was wrong.**
Previously `_deep_scan_worker` iterated hosts in a `for` loop (serial), and the subprocess cap was hardcoded at `360s` — less than Nmap's own `--host-timeout 5m` setting, so a slow host that Nmap needed its full 5 minutes to handle would be killed by Python's subprocess timeout instead, with a misleading error. Now uses `concurrent.futures.ThreadPoolExecutor` (default `max_workers=3`, configurable via `ASEP_DEEP_SCAN_CONCURRENCY`). Per-host subprocess timeout now equals `ASEP_DEEP_SCAN_HOST_TIMEOUT` (default 480s) so Python's cap always gives Nmap its full slot. After the batch completes, automatically triggers asset/service intelligence + vulnerability correlation reasoning via the skill engine. The old 30-minute failure-retry backoff and duplicate-scan prevention logic are preserved unchanged.

**2. Internet connectivity check and provider health — built from scratch.**
`app/provider_health.py` (`ProviderHealth`): background thread checks (1) internet via HTTP HEAD + TCP fallback to 8.8.8.8:53, (2) Ollama at `ollama_url/api/tags`, (3) OpenAI /models when an API key is present, (4) Claude Code presence+internet assumption. State values: `ONLINE/OFFLINE/AVAILABLE/UNAVAILABLE/DEGRADED/CHECKING/WORKING/ERROR`. `LLMRouter.ask()` and `reason_with_skill()` now call `set_working()`/`clear_working()` on the health monitor so the dashboard shows `WORKING` during real LLM calls. `/api/provider-health` (new endpoint) and `/api/intelligence/status` (enriched) expose the state. 14 tests including thread-safety and both offline probe paths.

**3. Dashboard and Settings UI.**
Dashboard LLM pill now shows: internet icon (🌐/✗/…) + mode + current task when active; sub-status line below shows provider state + seconds-since-last-check. Settings page now shows Internet, Provider health breakdown, and Claude Code fields. Claude usage: correctly states "Estimate: unavailable from here — check claude.ai/usage" (Claude Code uses OAuth subscription auth; ASEP has no way to read the quota without making a billed call). Never fabricates a percentage; distinguishes ESTIMATED from AUTHORITATIVE per Stage 2 spec.

**Full suite: 176/176 passing (17 new this release).**

## v2.9.32 — 75-Skill Upgrade Tahap 1: Persistent Skill Registry
Operator uploaded `ASEP-All-Skills-v1.0-75-Skills.zip` (75 skills across 28 categories, `skill-registry.json`, `README.md`, `SHA256SUMS`) with a master upgrade document. This release is Tahap 1 (foundation) of that roadmap — inspected first per the document's own "no blind rewrite" instruction before any code changed.

- **Verified before use**: all 77 package entries (75 skills + README + registry) checked against `SHA256SUMS` — passed. Confirmed the first 18 skills in this package are a more formally structured re-authoring (YAML frontmatter, explicit "ASEP Core Boundary" section per file, standardized Output Contract) of the ones integrated in v2.9.30, not identical files — so this is a genuine upgrade, not a duplicate.
- **`app/skill_registry.py`** (new): `parse_skill_markdown()` safely parses YAML frontmatter (via `yaml.safe_load` only — never executes skill content), `seed_builtin_skills()` idempotently loads all 75 into the new persistent registry, `select_skills()`/`build_skill_prompt()` form the DB-backed Skill Router (replacing the static 18-skill dict as the live path). 19 new tests, including explicit non-execution proof for skill content containing code-like text.
- **`app/db.py`**: new `skill_registry` and `skill_registry_history` tables. `upsert_skill()` never silently overwrites — the row being replaced is archived to history first, supporting the rollback requirement in the master doc's Section 8. Confirmed `reset_network_state()` (environment-change cleanup) does not touch these tables — skills persist across restart and network changes alike.
- Skills ship with the app (`app/skills_seed/`, source-controlled) and are copied into `data/skills/` (the operator-visible, persistent skill directory) on first seed — matching Section 6 of the master doc.
- `LLMRouter.reason_with_skill()` and `GET /api/skills` now draw from the full 75-skill registry. `app/skill_prompts.py` (the old static 18) is kept, unmodified, for backward compatibility with its own existing test file — it is simply no longer the live selection path.
- `create_app()` now defensively ensures the DB schema exists and seeds skills (both idempotent) rather than assuming the caller always initializes first — closes a latent gap a pre-existing regression test exposed.

**Not yet done (explicitly deferred to Tahap 2+):** GUI skill upload (.md/.zip), hot-reload UI, dependency validation, self-test pipeline, Intelligence Command Center dashboard panel, Hypothesis/Information-Gain/Planning engines, continuous intelligence event queue, streaming.

**Full suite: 159/159 passing (20 new this release: 19 in test_skill_registry.py, 1 endpoint-count fix).**

## v2.9.31 — Captive Portal / Client Isolation Diagnostic
Operator was testing their own lab with a simulated captive portal and found the Live Assets & Observed Services table silently empty with no explanation.
- `network_discovery.py::discover()` now returns a `network_diagnostic` field when it finds zero hosts, or only the gateway with no other clients — the two patterns most commonly caused by (a) a captive portal blocking nearly all traffic pre-authentication, or (b) client/AP isolation on the access point (a very common default on guest/hotel/hotspot APs that persists even after login). Threaded through `ux.py::dashboard()` to the existing `/api/v2/dashboard` response.
- Live Assets panel now shows the likely causes and concrete next steps (check the AP's admin panel for a "Client Isolation" setting if it's the operator's own AP; note that isolation on someone else's network is a deliberate control, not something to bypass) instead of a bare "no hosts" message.
- 3 new tests (zero-hosts, gateway-only, and a confirmation that normal multi-host results get no diagnostic noise). Informational only — no scope, authorization, or scanning behavior changed.

**Full suite: 139/139 passing.**

## v2.9.30 — Fase 1 Hybrid-LLM Autonomy: Skill Library + LLM-Backed Replanner + GUI Interconnection
Operator supplied 18 ASEP skill definitions (evidence, asset/service, vulnerability correlation, attack path, adaptive replanning, failure intelligence, capability/tool selection, metasploit, session, network, web/API, AD/identity, cloud, wireless, source code, OSINT, risk, reporting intelligence) and asked to make ASEP autonomous, with all GUI menus interconnected. This release is Fase 1 (skill-augmented reasoning); Fase 2 (persistent mission loop) is explicitly deferred and scoped separately given its safety weight (Section 39/65 of the master ASEP instructions — autonomy must never bypass scope, authorization, or approval gates).

- **`app/skill_prompts.py`** (new): all 18 skills stored verbatim (spot-checked against the uploaded files by SHA-256 content hash — not re-derived or summarized), with `select_skills()` (keyword-scored auto-selection, evidence_intelligence always included as baseline) and `build_skill_prompt()` (assembles the reasoning prompt, always appends an "ASEP CORE AUTHORITY... cannot be changed by it" disclaimer so a skill's prompt can never be mistaken for an instruction that overrides scope/approval). 11 tests, including a content-integrity check.
- **`LLMRouter.reason_with_skill(context, skill_ids=None)`**: routes a skill-augmented prompt through whichever backend `ask()` resolves to (cloud/local/claude_code) — no separate wiring needed per backend. 3 new tests (mocked, no real LLM required).
- **Significant finding, fixed:** `app/replanner.py::Replanner` was previously 100% rule-based — five hardcoded candidate actions, zero LLM calls — despite being described in earlier release notes as ASEP's adaptive-reasoning engine. It now gets *additive* LLM-backed reasoning (`adaptive_replanning` + `failure_intelligence` skills) as a new `llm_reasoning` field; the original deterministic `candidate_actions` list is completely unchanged in shape and ordering, an LLM failure is caught and surfaced without breaking replanning, and the zero-argument `Replanner()` constructor remains fully backward compatible (existing test suite passes unmodified). 5 new tests.
- **New endpoints**: `GET /api/skills` (list all 18), `POST /api/skills/reason` (direct skill-augmented reasoning, any UI panel can call it, logged to the evidence trail). 6 new Flask test-client integration tests.
- **GUI interconnection** (explicit operator request — "semua menu GUI ASEP harus saling terkoneksi"): new "Skill Reasoning" panel on the Intelligence page (skill picker defaulting to Auto, context box, result display). A global `runSkillReasoning(context, skillId)` connector lets any page jump to this panel pre-filled and pre-run in one click — wired from the Target Inventory exploit-candidates box (🧠 button per service, using `vulnerability_correlation`) and the Attack Paths page (🧠 button using `attack_path_intelligence`, summarizing the currently loaded candidate paths). A regression test locks in that both entry points and the panel itself stay wired together.
- During implementation, an editing mistake briefly deleted the `runIntelligence` function declaration while inserting the new code nearby; caught immediately by `node --check` before any commit, not shipped.

**Full suite: 136/136 passing (25 new this release).**

## v2.9.29 — Live Asset Monitoring Fix + Deep-Scan Failure Markers + Mobile/Android Detection

**1. Live Assets & Observed Services — always-current monitoring.**
- **Root cause of staleness (confirmed by reading the code, not assumed):** the 5-second dashboard poll only called `loadDashboard()` (which refreshes the Live Assets table) when discovery status was `running`, or when the table was empty. Once discovery settled to `ready` with hosts present, the table stopped auto-refreshing entirely — a host marked offline by the existing 30-second continuous-awareness cycle would stay visible until a manual refresh.
- **Fix:** the poll now calls `loadDashboard()` unconditionally every 5s while the tab is visible.
- What was already correct and needed no change: offline hosts were already filtered out of the Live Assets table (`state` not in up/local/reachable); newly discovered IPs were already added to the inventory immediately and auto-deep-scanned (`_maybe_auto_deep_scan`, with a 30-minute retry backoff on failure so a broken host doesn't loop forever).

**2. Deep-scan failures — marked per IP, not just an aggregate count.**
- The backend already tracked `failed_hosts` (target, error, state) per host with a 30-min retry backoff; the UI only ever showed a total count ("3 failed"). Now each failing IP gets a `⚠ DEEP SCAN FAILED` badge (with the actual error in a tooltip) directly on its row, in both the Live Assets table and Target Inventory cards.

**3. Mobile phone / Android detection, with brand identification.**
- `infer_asset_type()` (`app/identity_enrichment.py`) gained phone detection: hostname patterns (`iphone`, `android-*`, `galaxy`, `redmi`, `pixel`, etc. — medium confidence, brand extracted directly) and a short vendor-OUI-only list for phone-first manufacturers (Samsung, Xiaomi, Huawei, OnePlus, OPPO, Vivo, Realme — low confidence, with an explicit "also makes non-phone devices" caveat, since OUI alone can't distinguish a phone from a TV/appliance from the same maker). Apple/Google/Motorola/Nokia are deliberately excluded from the vendor-only path (too product-line-ambiguous) and only match via hostname pattern, to avoid a false "Mobile Phone" claim on a MacBook or Nest device — covered by regression tests.
- New `Target.asset_brand` field threads the detected brand through `/api/v2/targets`, the Attack Graph node payload, and the UI: Live Assets table gained a DEVICE column, Target Inventory cards show a Device line, Attack Graph gained a smartphone icon and shows brand in the node tooltip.
- 6 new tests (12 total in the identity-enrichment suite), including explicit non-regression checks (bare Apple OUI without a phone hostname is not claimed as a phone; MacBook hostname still classifies as Laptop).

**Full suite: 111/111 passing (6 new this release).**

## v2.9.28 — LLM Mode Switch (GUI) + Dashboard LLM Badge + Target Inventory Exploit Candidates
Three operator-requested features in one release.

**1. Tahap A3 — switch LLM mode from the GUI, not just view it.**
- `app/config.py::persist_env_var()`: safely updates one `KEY=value` line in `.env`, leaving every other line (including secrets like `OPENAI_API_KEY`) byte-for-byte untouched. 4 unit tests.
- `POST /api/settings/llm-mode` validates the value (`auto`/`cloud`/`local`/`claude_code`), mutates the live `cfg` dict for immediate effect (no restart — `LLMRouter` reads `cfg` by reference), and persists to `.env`. 3 new tests use a real Flask test client (not just source inspection) to verify the full round trip: immediate effect, on-disk persistence, secret preservation, and rejection of invalid values.
- `/api/intelligence/status` now also returns `requested_mode` (the raw setting) alongside `mode` (the resolved/active one), so a UI control can reflect "auto" even when the resolved mode is concretely "cloud".
- Settings page: new LLM mode dropdown + Apply button, wired to the endpoint.

**2. Dashboard: always-current LLM status badge.**
- New color-coded pill at the top of the main dashboard (not just Settings), reading the same authoritative `/api/intelligence/status` used everywhere else. Refreshed on dashboard load and on the existing 5-second poll, so it reflects a mode switch made from another tab/session without a manual refresh. Click jumps to Settings.

**3. Target Inventory — exploit candidates per asset, evidence-gated.**
- New `app/exploit_candidates.py`. For each of a target's services, but **only services with an actual product/version fingerprint** from a real scan (a bare open port with no identification is skipped, not guessed at), it checks three independently real sources:
  - local Metasploit module search, via the operator's own installed `msfconsole` (`app/metasploit.py::search_modules`) — never a hardcoded module catalog;
  - public NVD CVE keyword search (`app/internet_research.py::nvd_cves`), gated by `ASEP_INTERNET_RESEARCH_ENABLED`;
  - ASEP's own local tool registry (`app/tool_registry.py`), matched by service name, filtered to tools actually detected installed on this machine.
  Every result is explicitly labeled `CANDIDATE` with a verification note — nothing is ever reported as confirmed-exploitable. During implementation a real bug was caught and fixed by its own test: the certainty gate initially still fell back to a bare service name (e.g. "http") when no product/version was present, defeating the "must be certain first" requirement — it now requires an actual fingerprint before querying anything.
- New endpoint `GET /api/v2/targets/<address>/exploit-candidates`, logged to the evidence trail.
- Target Inventory: new "🔎 CEK KANDIDAT EXPLOIT" button per asset card, results render inline in that same card (no navigation away), with a standing disclaimer banner.
- 7 new mocked unit tests (no real msfconsole/network required).

**Total new/changed tests this release: 21. Full suite: 105/105 passing.**

## v2.9.27 — LLM Mode Visibility Fix (Settings)
Operator asked "where can I see which LLM ASEP is currently using?" — investigating surfaced a real bug this exposed.
- **Root cause:** `/api/intelligence/status` computed its `mode` field with its own separate, hard-coded heuristic (`"hybrid" if local+cloud else local/cloud/none`) that predates `LLMRouter.mode()` and had no notion of the `claude_code` backend added in v2.9.26. Result: the Settings page's "LLM mode" line would report `none` even when Claude Code was explicitly enabled and actively being used by every real call through `LLMRouter.ask()`.
- **Fix:** the route now calls `llm.mode()` directly — the exact same resolution `ask()` uses at call time — so the displayed value can never drift from actual behavior. The response also gained a `claude_code` block (`enabled`, `installed`, `binary_path`).
- Settings page (`loadSettings()`) now shows a dedicated "Claude Code" status line: enabled+found / enabled+CLI-missing / CLI-found-not-enabled / not-installed, plus relabeled "LLM mode" to "LLM mode (active now)" for clarity.
- 2 new regression tests locking in the fix (source-inspection based, no Flask test client needed, consistent with this file's existing style) so the old heuristic can't silently creep back in.
- **Known limitation, unchanged:** this is view-only. Switching which backend is active still requires editing `.env` (`ASEP_LLM_MODE`) and restarting ASEP — a settings-page control to switch it live is a separate, not-yet-built feature (Tahap A3).

## v2.9.26 — Hybrid LLM: Claude Code Reasoning Backend + Automated Local LLM Install
Fase A1 of the operator-requested hybrid LLM roadmap (reasoning-only first; self-modification/coding-agent use is a separate, later phase with its own approval-workflow design).
- **New LLM backend: Claude Code.** `LLMRouter.ask_claude_code()` shells out to the operator's own, already-authenticated `claude` CLI in headless mode (`claude -p ... --output-format json`), using their existing Pro/Max subscription login — not a separate Anthropic API key.
  - Deliberately does **not** pass `--bare`: bare mode disables OAuth/subscription auth entirely and requires `ANTHROPIC_API_KEY` instead, which would defeat the purpose of reusing an existing subscription.
  - Deliberately does **not** pass `--allowedTools`: this backend is reasoning-only, with the same `{mode, text}` contract as the existing Cloud/Local backends — zero file, bash, or tool access.
  - Passes `--permission-prompts none` (the officially documented pattern for unattended runs with nobody present to approve a prompt) so any tool attempt is cleanly denied instead of hanging, plus `--max-turns` as a hard ceiling.
  - Runs from an isolated scratch working directory (`data/llm_cc_scratch/`), not ASEP's own project root, so it never picks up a stray `.claude/settings.json`, `.mcp.json`, or `CLAUDE.md` from this repo.
  - Clear, distinct error messages for: binary not found, timeout, non-JSON output, and empty output (covers both "not logged in" and "CLI too old for --permission-prompts, needs v2.1.259+").
- `llm_mode` now accepts `claude_code` explicitly; `auto` mode priority is cloud → claude_code (only if `ASEP_CLAUDE_CODE_ENABLED=true` and the binary is actually on PATH) → local → none.
- New config: `ASEP_CLAUDE_CODE_ENABLED` (default false — opt-in), `ASEP_CLAUDE_CODE_BINARY`, `ASEP_CLAUDE_CODE_TIMEOUT`, `ASEP_CLAUDE_CODE_MAX_TURNS`.
- `tests/test_llm_claude_code.py`: 11 new mocked tests (no real `claude` CLI required) — including explicit assertions that `--bare` and `--allowedTools` are never passed.
- **install.sh**: now actually installs Ollama (`curl -fsSL https://ollama.com/install.sh | sh`) and pulls the configured local model automatically — previously this was only printed as a manual instruction at the end. Also detects/installs the Claude Code CLI. Login remains a manual interactive step by necessity (OAuth device flow cannot be scripted); the installer prints the exact next step. Fixed stale hardcoded "v2.9.5" version strings in the installer banner/summary — now reads `VERSION` dynamically. Renumbered install steps 1–10.
- README: new "Claude Code backend" subsection under LLM configuration.

## v2.9.25 — Metric Icon Centering/Color Fix
Operator-reported bug: Targets/Services/Findings/Attack Paths/Sessions/Evidence Items icons weren't centered and had no visible color.
- **Root cause (confirmed by inspecting computed specificity):** `.metric span{display:block;color:var(--muted);...}` targets any `<span>` inside `.metric` — and `.metric-icon-wrap` is itself a `<span>`. Selector specificity is (0,1,1) for `.metric span` vs (0,1,0) for `.metric-icon-wrap`, so the generic rule won regardless of source order, silently overriding `display:grid` (which is what centered the icon via `place-items:center`) to `display:block`, and overriding the intended blue `color:#5bb8ff` to grey `var(--muted)`. The icon-wrap rule was never actually taking effect.
- **Fix:** rescoped the generic rule to `.metric-body span` — the sub-label text it was actually meant to style lives inside `.metric-body`, a sibling of `.metric-icon-wrap`, not inside it — so it no longer matches the icon wrapper at all.
- Also widened the Evidence Items document icon (was narrower than its siblings, making it look visually smaller/off-balance in the row even once centering was fixed).

## v2.9.24 — Functional Attack Graph (Real Topology + Real Asset-Type Icons)
Operator asked for the Attack Graph to resemble the reference mockup while explicitly cautioning against a purely cosmetic copy ("perhatikan fungsi utamanya, jangan hanya sekedar tampilan"). This release is scoped accordingly: everything visual is derived from real backend data, nothing is fabricated.
- **Node icons** are now keyed to the real `asset_type` field (`infer_asset_type()` in `identity_enrichment.py` — evidence-based, confidence-scored): Firewall, Router / Gateway, Network Switch, Wireless Access Point, Printer, NAS / Storage, Server / Host, Laptop / Endpoint, PC / Endpoint, Network Host. This replaces the mockup's fixed illustrative node set (Internet/Firewall/Web App/API/Database/DMZ/etc, which are not real ASEP data) with icons that reflect what was actually inferred about each discovered host, with the basis visible in the hover tooltip.
- **Layout** replaced the decorative index-order grid with a radial hub layout (`layoutRadial()`) computed from real edge adjacency: node degree is derived from the actual `default-gateway`/`lan-neighbor` relations already produced by `network_discovery.py`, the highest-degree node becomes the visual hub, and spoke radius adapts to node count (validated for 24-node sets matching real-world usage, with no overlaps). Falls back to a plain grid when there is no edge data (e.g. a fresh/empty environment).
- **Node card content**: bold label now prefers real hostname, falling back to the real asset type; IP is always shown; detail line shows real vendor. Removed a latent bug where the card referenced a non-existent `n.role` field on nodes (always undefined — the field is actually called `type`/asset_type in the API response).
- Edges are styled by their real `relations` (`default-gateway` vs `lan-neighbor`) rather than uniform styling.
- Metric-card icon plates polished (slightly larger, more vivid) to better match the reference mockup — cosmetic only, values are unchanged, no fabricated delta numbers.
- Legend/scope-status coloring unchanged from v2.9.22 — still only "In Scope" / "Local Candidate" / "Hypothesis link" / "Service" / "Evidence", since "Compromised" / "Blocked" / "High Risk" / "Out of Scope" from the mockup have no backing data in ASEP yet.

## v2.9.23 — Attack Graph Pan & Pipeline Overflow Fix
Operator-reported bugs from testing v2.9.22, both frontend-only, no backend/API changes.
- **Attack Graph escaping the CORRELATION panel.** Root cause: `.graph{overflow:auto}` combined with the box growing (`min-width`/`min-height`) to fit every node meant large asset sets rendered wider/taller than the panel. Fix: node/edge rendering now goes into an inner `.graph-viewport` div sized to fit the content, while the outer `.graph` box stays fixed-size and clips it (`overflow:hidden`) — nodes can no longer render outside the panel border.
- **Attack Graph is now pannable.** Added drag-to-pan (pointer events, mouse + touch) on the graph box so operators can navigate node sets larger than the visible area, replacing the removed scrollbar. Pan offset is clamped so content can never be dragged fully out of view, and is preserved (re-clamped) across the periodic dashboard refresh instead of resetting.
- **Pipeline stepper needed horizontal scrolling and clipped the OPERATIONAL status badge.** Root cause: `.top-actions` (status/version, right side of topbar) had no flex-shrink protection, so the wide two-line 7-stage stepper squeezed it off-screen. Fix: `.top-actions{flex:none}` so it's never compressed; pipeline stage buttons simplified to a single line (number + title, full description moved to a hover tooltip) with flexible shrink + ellipsis, so all 7 stages always fit in one row with no scrollbar.

## v2.9.22 — Dashboard Restyle (Mockup Stage 1)
Frontend-only restyle toward the operator-provided ASEP dashboard mockup. No backend/API changes.
- Metric cards: relabeled/reordered to Targets, Services, Findings, Attack Paths, Sessions, Evidence Items (all real `dashboard.metrics` fields) with per-category icons. No fabricated delta numbers ("+N today") were added — that would require a historical baseline the database doesn't track yet.
- Workflow stepper: replaced the old hardcoded 10-stage client-side array with the backend's already-returned 7-stage `dashboard.pipeline` vocabulary (Understand → Discover → Analyze → Validate → Exploit → Post-Exploit → Achieve), styled as numbered stage cards with subtitles.
- Fixed a pre-existing bug: pipeline-stepper click listeners were bound before `renderPipeline()` populated the DOM, so clicking any pipeline stage silently did nothing. Switched to event delegation on the stable `#pipeline` container.
- Attack Graph legend: added "In Scope" / "Local Candidate" entries driven by the real `scope_status` field already present on target nodes, plus a "Hypothesis link" entry for the existing hypothesis-edge styling. Did not add legend entries for states the backend doesn't track (e.g. Compromised/Blocked/High Risk from the mockup) to avoid implying capabilities that don't exist.
- Recent Findings / Active Sessions: row-style layout; session status is now color-coded from the real `status` field (active/sleeping/dead).
- Updated `tests/test_ux_contract.py` to assert the new 7-stage pipeline vocabulary and current version (superseding the old 10-stage assertion, which was the previous, now-replaced UX contract).

## v2.9.21 — Network Discovery Error-Handling Fix
- Fixed: `network_discovery.discover()` raised an uncaught `ScopeError` instead of returning the standard `{"ok": False, "errors": [...]}` result whenever no locally attached network currently matched the requested candidate (e.g. interface briefly down, DHCP renewal, Wi-Fi roaming, or the 30-second automatic continuous-awareness cycle firing with no active local IPv4 interface). This bypassed evidence/discovery-run persistence for that cycle and left cached dashboard status stale. `_select_candidate()` failures are now normalized into the same structured error contract as `run_nmap()` failures.
- Added regression test `test_discover_returns_structured_error_when_no_local_candidate` in `tests/test_environment_discovery.py`.
- No API, schema, or behavior changes on the success path.

## v2.9.20
- Persisted Services Deep Scan completion state across continuous network-discovery refreshes; dashboard and Targets inventory now retain a green `DEEP SCAN ✓` marker after completion.
- Metasploit buttons in Targets & Active Hosts are visually marked green for fast discovery.
- Added persistent deep-scan status derived from completed `deep_full` service-scan records, so the completion marker survives process refresh/restart.
- Added per-host progress timing and failure accounting to the deep-scan state.
- Added Nmap per-host timeout controls (`--host-timeout 5m`, `--max-retries 3`, `-T4`) and a process timeout so a slow/unresponsive host cannot stall the entire batch indefinitely. Failed hosts are skipped and the batch continues; final status becomes `ready_with_errors`.
- Dashboard now shows current-host elapsed time and explicit partial/error state.

# 2.9.19 — Dashboard & Remote Metasploit Candidate UX

- Dashboard live-host inventory now shows a green dot only after a target completes Services Deep Scan.
- Resource history chart now uses readable CPU/MEM colors based on current health.
- Deep Scan adds Nmap OS detection to the existing TCP-only 1–65535 service inventory; UDP port scanning remains disabled.
- Exploitation candidates are filtered to remote exploit modules with explicit CHECK support and compatible Nmap OS evidence; multi-platform remote exploits remain eligible.
- Removed Advanced manual module search from the Exploitation UI.
- CHECK result panel is structured and RUN lock state now explains the exact reason (required, not vulnerable, inconclusive, or error).

# v2.9.18 — Metasploit Remote Candidate Accuracy

- Exclude local privilege-escalation/post/payload modules from Target Inventory remote candidates.
- Validate candidate modules expose RHOST/RHOSTS before display.
- CHECK/RUN dynamically use RHOST or RHOSTS instead of blindly setting RHOSTS.
- Carry matched service RPORT into CHECK/RUN.
- Add Target Inventory regression coverage for false-positive local modules.

## 2.9.17 — Resource Health Color Coding

- Dashboard Local Resource cards now show readable health states: LOW, MODERATE, HIGH, CRITICAL.
- CPU, memory, and disk bars/value text change color by utilization.
- Critical state starts at 95%; 100% is always red/CRITICAL.
- Numeric utilization remains visible and status text accompanies color so color is not the only signal.

## v2.9.16 — Automatic Target-Inventory Metasploit Correlation

- Exploitation now receives the selected target directly from Target Inventory.
- Added automatic Metasploit candidate discovery from persisted service/port/product/version evidence.
- Candidate search uses Metasploit module metadata queries and never executes a module.
- Target Service Intelligence is displayed on the Exploitation page.
- CHECK remains required before any consequential Metasploit action; RUN remains approval-gated.
- Advanced manual module search remains available.
- Persisted service evidence remains the source for the candidate search.
- Deep Scan remains TCP 1-65535 only; UDP is not scanned.

# v2.9.15 — Runtime Smoke Fix

- Fixed `NameError: _ensure_auto_awareness is not defined` raised by `/api/v2/dashboard`.
- Restored the existing lightweight 30-second automatic network-awareness trigger.
- Dashboard access no longer fails before returning network/intelligence state.
- Comprehensive service Deep Scan behavior is unchanged: TCP 1–65535 only; UDP is not scanned.
- Added regression coverage for the auto-awareness function and dashboard trigger wiring.

## v2.9.14 — Target Inventory Service Intelligence

- Persisted deep-scan service inventory is authoritative for Target Inventory after a completed scan.
- Target Inventory / Targets & Active Hosts displays identified ports and detailed service metadata on target detail.
- Dashboard network table displays identified ports only; service/product/version details stay in Target Detail.
- Targets with identified service evidence expose a METASPLOIT action that opens the target in the Metasploit workflow; execution remains behind CHECK → explicit approval.
- Preserved TCP-only deep scan (1–65535); UDP is not scanned.

# v2.9.13

- Persist completed TCP deep service scans in SQLite `service_scans` and `service_inventory`.
- Preserve raw Nmap XML for tool interoperability and later workflow stages.
- Persist service/version/CPE/confidence/reason metadata from Nmap XML.
- Target detail and service API now read the persisted normalized inventory.
- Added per-target and whole-environment Nmap XML export endpoints suitable for downstream tooling such as Metasploit `db_import`.
- Network reset removes environment-derived service inventory together with targets/evidence, preventing stale network data after reboot/new environment.

# v2.9.12 — Reboot-Safe Network Environment Cleanup

- Added lifecycle tracking for Linux boot ID and current network identity (CIDR, interface, local IP and gateway).
- On the next laptop boot, network-derived targets, service/port evidence and discovery-run history are cleared before discovery starts.
- A changed DHCP/network identity is also detected by the persisted lifecycle marker.
- Audit history, configuration, skills and source code are preserved.
- Added regression tests for reboot cleanup, DHCP/network changes and unchanged environments.
- Deep Scan remains TCP 1–65535 only; UDP is not scanned.

# v2.9.11 — TCP-Only Comprehensive Service Inventory

- Deep/comprehensive service inventory now scans **TCP 1-65535 only**.
- UDP is excluded from the automatic and manual deep-scan workflow.
- Service/version detection remains enabled with `-sV --version-all --allports`.
- Dashboard scan scope/evidence labels now report `TCP 1-65535`.
- Added regression coverage ensuring `-sU` is not part of `deep_full`.

# v2.9.10 — Automatic Comprehensive Service Inventory

- Deep scan now starts automatically after live-host discovery.
- TCP+UDP ports 1–65535 are scanned with full Nmap service/version detection.
- The heavy scan is not repeated on the 30-second awareness cadence.
- Newly discovered local hosts are queued for comprehensive scanning.
- Dashboard refreshes after scan completion and replaces/enriches service inventory.
- `RESCAN ALL SERVICES` forces a fresh comprehensive batch.
- Added per-network scanned-host ledger and batch reason/status.

# v2.9.9 — Comprehensive Network Service Inventory

- Added explicit full network scan for currently live local hosts.
- Comprehensive scan uses TCP+UDP all ports with Nmap version detection and XML evidence.
- Deep scan is operator-triggered and is not part of the 30-second awareness loop.
- Dashboard shows deep-scan progress and observed ports/services after completion.
- Live asset inventory now carries observed port/service details.
- Added regression coverage for the deep scan profile.

# v2.9.8 — Continuous Network Awareness & Automatic Asset Discovery

- Dashboard-triggered automatic local environment detection and host discovery.
- 30-second minimum network discovery cadence.
- 10-second lightweight resource telemetry.
- Dashboard shows current network, local IP, gateway, DNS and interface.
- New/changed local assets automatically enter inventory and are queued for service discovery.
- Previously seen hosts not observed in the current cycle are marked offline without changing last-seen history.
- Automatic service discovery is restricted to directly connected local IPv4 hosts.
- Clean live-host inventory and adaptive large-network Asset Graph.

# v2.9.7-fixed — Runtime/Test Regression Fix

- Fixed Flask route creation when `cfg["root"]` is a string by normalizing it with `pathlib.Path`.
- Updated UX version contract from 2.9.6 to 2.9.7.
- Added regression coverage for string-root route creation where the service-evidence test suite permits it.

# v2.9.7 — Continuous Network Awareness

- Automatic environment/network detection on dashboard access
- Continuous lightweight network discovery with 30-second minimum interval
- Live host inventory and new-device detection
- Automatic service-discovery queue for newly observed hosts
- Automatic environment adaptation when moving to a directly connected network
- Dashboard network identity: CIDR, local IP, gateway, DNS, interface
- Lightweight 10-second resource telemetry
- Clean dashboard information hierarchy
- Large-network Attack Graph layout improvements
- Evidence/accuracy and scope safeguards documented

## 2.9.6 — Service Evidence & Manual Workflow

- Fixed the target-detail evidence path: raw evidence `data` is now available to focused consumers without changing the default evidence listing contract.
- Added dedicated `service_scan` evidence for `validate_services`.
- Service scan results are normalized into observed services and persisted into target metadata.
- Target inventory service counts now reflect observed open/identified services.
- Target detail now displays PORT, PROTO, STATE, SERVICE, PRODUCT / VERSION and DETECTION.
- Added refresh service discovery action when services are already present.
- Added a clear empty state when service discovery completed but no open/identified service was observed.
- Updated the top workflow pipeline to match the ASEP manual: ENV → DISCOVER → IDENTIFY → SERVICES → ANALYZE → VALIDATE → PATH → ACTION → SESSION → REPORT.
- Added `UX_GUIDE.md` for the complete v2.9.6 operator workflow.

## 2.9.5 — Intelligence Workflow UX Patch

- Reworked **ASEP Intelligence** into an evidence-first mission-readiness view.
- Added deterministic readiness gates for Environment, Discovery, Identity, Service, Platform, Analyze, Validate, Attack Path and Action.
- Added environment understanding, knowledge gaps, metrics and Next Best Action panels.
- Kept deep LLM output secondary/collapsible instead of exposing raw engine JSON as the primary UX.
- Added `/api/v2/intelligence/summary` read-only aggregation endpoint.
- Preserved local/offline intelligence operation; cloud LLM remains an optional enhancement.

# Changelog

## 2.9.12 — Reboot-Safe Network Environment Cleanup
- Added network environment lifecycle tracking using the Linux boot ID and current primary interface/network/IP/gateway identity.
- On a new laptop boot, ASEP clears network-derived targets, service/port evidence and discovery-run history before automatic discovery starts.
- If the environment marker is missing but stale network inventory exists, ASEP performs a one-time cleanup.
- Audit history, configuration, skills and application source are preserved.
- The cleanup state is persisted under `data/environment_state.json`.
- Added regression tests for reboot cleanup, DHCP/network changes and unchanged environments.
- Deep Scan remains TCP-only: TCP 1–65535 with service/version detection; UDP is not scanned.


## 2.9.4 — Asset Intelligence & Dashboard Resource UX
- Asset graph is now the dashboard default view.
- Added inferred asset type from vendor, hostname, role and observed services.
- Added explicit inference confidence/basis so MAC vendor is not treated as exact hardware form factor.
- Added read-only target detail modal from graph nodes.
- Added observed service table from stored scan evidence.
- Added evidence detail modal with raw evidence payload.
- Added compact CPU, memory, disk and network resource telemetry graph for the ASEP laptop.
- Preserved scoped execution and host-discovery-only defaults.

# ASEP v2.9.2 Runtime Fix

- Fixed runtime smoke failure when the optional `openai` Python SDK is not installed.
- OpenAI SDK is now imported lazily only when Cloud LLM mode is actually used.
- Offline/local ASEP startup and runtime validation no longer depend on the OpenAI SDK being present.
- Added regression tests for optional OpenAI dependency behavior.

# Changelog

## 2.9.2 — Environment Awareness & Active Host Inventory

- Added passive local environment detection for connected IPv4 networks.
- Added automatic interface, gateway, network/CIDR and network-kind detection.
- Added explicit confirmation gate before active host discovery.
- Added Nmap host-discovery-only profiles: automatic, ARP, ICMP and TCP.
- Added active host inventory with IP, hostname, MAC, vendor, interface and role when available.
- Added persistent target inventory in SQLite.
- Added discovery run history and evidence records.
- Added new/known host accounting.
- Added local-candidate scope state so a detected lab network is not silently promoted to permanent assessment scope.
- Added environment-aware Targets UI and Network Discovery UI.
- Kept service discovery, vulnerability validation and exploitation behind the existing normal scope controls.
- Extended Nmap XML parsing with MAC/vendor metadata.
- Preserved v2.8.2 core execution and v2.9.1 UX architecture.

## 2.9.3 — Environment Identity Enrichment
- Active-host discovery now requests reverse DNS names with Nmap `-R` while retaining `-sn` host-discovery-only behavior.
- Every discovered MAC is normalized and enriched immediately using Nmap/arp-scan local registries.
- Locally administered/randomized MACs are explicitly labeled instead of being assigned a false manufacturer.
- Added system resolver fallback (`getent`) for hostnames.
- Discovery results retain identity provenance (`hostname_source`, `vendor_source`, MAC flags).
- UI should display hostname and manufacturer as first-class inventory fields.

## v2.9.5
- Local Resource panel moved to the top of Mission Control.
- Multi-source MAC/OUI provenance from Nmap, arp-scan/IEEE-compatible local registries and MAC flags.
- Logical role inference using gateway/routing, hostname, vendor and observed services.
- Asset Graph enriched with role, hostname, manufacturer and logical topology edges.
- Target detail now shows identity sources, topology basis and observed services; explicit service validation is available when no service evidence exists.
- Patch: LAN-neighbor topology edges now originate from ASEP's local IP; gateway edges remain a separate default-gateway relation. Duplicate `(from,to)` edges are merged with `relations` provenance.
- Patch: added `.detail-subtitle` styling for target detail identity subtitles.
- Review fix: `ASEP_ROOT_APPROVAL_REQUIRED` is now read from configuration instead of being hardcoded.
- Review fix: removed the duplicate `loadCapabilities()` definition in `static/app.js`.
- Review fix: installer package coverage is aligned with the registered Kali tools, including the `httpx-toolkit` binary/package naming.
- Review fix: systemd installation now accounts for the optional self-modifying source-write lifecycle instead of silently blocking it under `ProtectHome=read-only`.
- Review fix: non-loopback service binds require HTTP Basic Auth; localhost remains the default passwordless lab mode.
- Review fix: wired existing tool-plan/run/chain, target-path, adaptive/replan, Windows fingerprint, wireless chain, self-modifying apply and shell/sudo endpoints into the operator UI.
- Model note: the current OpenAI model catalog documents `gpt-5.6-luna` as a valid Luna model ID, so the prior review finding that this identifier was invalid was not applied as a downgrade/change.
