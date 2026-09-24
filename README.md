# ASEP v2.9.6

Universal Security Intelligence UX over the validated v2.8.2 core.

# ASEP v2.9.1

**Adaptive Security & Exploitation Platform** — Universal Security Intelligence & Exploitation Platform for authorized security assessment on Kali Linux.

## Release status

- Release: **2.9.6**
- Environment awareness: **enabled**
- Active host inventory: **enabled**
- Host discovery default: **Nmap -sn only**
- Automatic service scanning after discovery: **disabled**
- Version source: `VERSION`
- Runtime: Python 3.10+ / Flask 3.x
- Self-modifying engine: **disabled by default**
- Core engine tests in this release baseline: **17**
- Route contract test: **PASS**
- Runtime smoke: designed to require the installed Flask runtime and project-root import path

## What changed in 2.8.2

- Fixed `validate_build.sh` runtime-smoke import path (`PYTHONPATH` now points to the project root).
- Added a single release-version source in `VERSION`.
- API status now reports the release version from `VERSION` rather than a hard-coded value.
- Added a runtime-smoke assertion that the API version matches `VERSION`.
- Standardized release/package/installer naming to **ASEP v2.8.2**.
- Kept the existing intelligence, evidence, scope, attack-path, Metasploit, session, self-healing, and self-modifying engines intact.

## Architecture

```text
Browser / UX
     |
     v
ASEP Intelligence Engine
     |
     +--> Scope & Policy
     +--> Capability Router
     +--> Evidence Engine
     +--> Attack Path / Re-planning
     +--> Tool Orchestrator
     +--> Metasploit Universal Capability
     +--> Session / Post-Session Intelligence
     +--> Self-Healing
     +--> Controlled Self-Modifying Engine
     |
     v
Kali execution + evidence store
```

ASEP is objective/evidence driven: the UI should express security objectives, evidence, hypotheses, validation state, and attack paths rather than making individual tools the primary abstraction.

## Install on Kali Linux

```bash
chmod +x install.sh validate_build.sh asep
./install.sh
source .venv/bin/activate
```

Validate:

```bash
ASEP_REQUIRE_RUNTIME=1 ./validate_build.sh
```

A complete runtime validation requires the dependencies from `requirements.txt`, including Flask. The validator also performs the 17 core tests and route-contract test. The runtime smoke uses Flask's test client to exercise API endpoints.

Flask documents `test_client()` as the standard application test client and recommends an application-factory structure for larger applications. See the official Flask documentation for those testing patterns.

Start locally:

```bash
./asep
```

Open:

```text
http://127.0.0.1:8000
```

For production deployment, use an appropriate production WSGI server rather than Flask's development server.

## Scope

Edit:

```text
config/scope.yaml
```

Example:

```yaml
engagement:
  name: home-internal-lab

scope:
  networks:
    - 192.168.1.0/24
  hosts: []

restrictions:
  dos: false
  destructive_testing: false
  data_modification: false
  scope_expansion: false
```

Out-of-scope assets are not actively tested. Passive deep-dive correlation can be used to determine whether a discovered asset is relevant before requesting scope confirmation.

## Portable lab environment discovery

ASEP no longer requires a known CIDR before it can identify the current lab network. The **Targets & Active Hosts** view first performs passive local environment detection and shows connected IPv4 network candidates.

The active phase requires an explicit user confirmation and is restricted to a network that is currently attached to a local interface. The first active phase is host discovery only; it does not automatically port-scan every discovered host.

Detected hosts are stored in the target inventory with available IP, hostname, MAC, vendor, interface, role and discovery metadata. A newly detected network is labeled `LOCAL-CANDIDATE` unless it is already present in `config/scope.yaml`; it is not silently promoted to permanent assessment scope.

See `ENVIRONMENT_DISCOVERY.md` for the API and workflow.

## LLM configuration

The `.env.example` file contains the supported configuration. For a lightweight X230 local model:

```text
ASEP_LOCAL_ENABLED=true
OLLAMA_URL=http://127.0.0.1:11434
ASEP_LOCAL_MODEL=qwen3:0.6b
ASEP_LOCAL_NUM_CTX=2048
ASEP_LOCAL_NUM_PREDICT=256
ASEP_LOCAL_NUM_THREADS=2
ASEP_LLM_MODE=auto
```

Cloud reasoning can be configured separately with the appropriate API credentials and model setting.

### Claude Code backend (hybrid, uses your own subscription)

ASEP can use a locally installed Claude Code CLI as a third reasoning backend, in addition to Cloud and Local. It authenticates through your own Claude Code Pro/Max login (`claude` CLI), not a separate API key, and is invoked headlessly with zero file/bash/tool access — it is a pure reasoning backend with the same `{mode, text}` contract as Cloud/Local (see `app/llm.py::ask_claude_code`).

```text
ASEP_CLAUDE_CODE_ENABLED=false
ASEP_CLAUDE_CODE_BINARY=claude
ASEP_CLAUDE_CODE_TIMEOUT=120
ASEP_CLAUDE_CODE_MAX_TURNS=4
```

Setup (also automated by `install.sh`):

```bash
curl -fsSL https://claude.ai/install.sh | bash
claude   # run once, interactively, to log in with your subscription
```

Then set `ASEP_CLAUDE_CODE_ENABLED=true` (and optionally `ASEP_LLM_MODE=claude_code` to force it instead of auto-detect priority: cloud → claude_code → local).

## Self-modifying safety defaults

```text
ASEP_SELF_MODIFY_ENABLED=false
ASEP_SELF_MODIFY_APPROVAL_REQUIRED=true
ASEP_SELF_MODIFY_MAX_FILE_BYTES=500000
```

The controlled lifecycle is:

```text
PREVIEW -> APPROVAL -> CHECKPOINT -> PATCH -> COMPILE -> TEST -> ACTIVATE
                                                      |
                                                      +-> ROLLBACK on failure
```

## Release consistency

The authoritative version is stored in `VERSION`.

## v2.9.6 Service Evidence & Workflow

- Fixed target-detail service evidence retrieval so stored scan payloads are available to the UX layer.
- Added dedicated `service_scan` evidence for service/version validation.
- Target inventory service counts now reflect observed open/identified services.
- Target detail now shows port, protocol, state, service, product/version and detection method.
- Updated the top workflow pipeline to explicitly expose Environment, Discovery, Identity, Services, Analysis, Validation, Path, Action, Session and Report.
- Added the v2.9.6 operator manual in `UX_GUIDE.md`. Release scripts and the API read that value rather than maintaining independent hard-coded release numbers.

## Project tree

```text
ASEP-v2.8.2/
├── VERSION
├── README.md
├── CHANGELOG.md
├── RELEASE.md
├── validate_build.sh
├── install.sh
├── asep
├── app/
├── config/
├── skills/
├── static/
├── templates/
└── tests/
```

## Runtime dependency note

The OpenAI SDK is optional for offline/local ASEP operation. It is loaded only when Cloud LLM mode is used. Install it with `python3 -m pip install openai` when Cloud LLM is enabled.

## Comprehensive Network Scan (v2.9.12)

After automatic discovery populates the live-host inventory, ASEP automatically starts a comprehensive inventory batch for the currently live hosts on the directly connected local network. It checks TCP ports 1–65535 and performs full Nmap service/version detection. UDP is not scanned. The heavy scan is not repeated every 30 seconds; the awareness loop remains lightweight. Newly discovered hosts are queued for the same comprehensive scan. **RESCAN ALL SERVICES** forces a fresh full batch.

Results are persisted as `deep_service_scan` evidence and replace/enrich the target port/service inventory. The dashboard refreshes its metrics and live asset/service table after the batch completes. A port being open or a service being identified is observation/evidence, not a vulnerability finding.

## Network Environment Cleanup (v2.9.12)

ASEP treats discovered targets, service/port evidence and discovery-run history as data belonging to the current laptop/network environment. On the next OS boot, ASEP detects the new boot identity and clears that network-derived state before starting discovery. A changed DHCP address/network identity is also recognized when the lifecycle marker is compared. Audit history, application configuration, skills and source code are retained. The next automatic discovery therefore starts from the IP address, CIDR, interface and gateway currently assigned to the T430u.
