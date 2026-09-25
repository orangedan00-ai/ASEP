# ASEP — Specialist Domain Architecture

**Status:** Official architectural concept  
**Scope:** Architecture and roadmap definition only; this document does not activate new runtime capabilities by itself.

## 1. Purpose

ASEP uses a **Specialist Domain Architecture** to keep different security-assessment disciplines separated by expertise while retaining a single central controller.

The core principle is:

> **ASEP controls the mission and orchestration; Specialist Domains own domain expertise; Skills provide capabilities; Tools execute capabilities; Evidence and outcomes return to ASEP.**

This prevents unrelated technical logic from being mixed together while allowing ASEP to combine results across domains.

## 2. High-Level Architecture

```text
                              ┌──────────────────────┐
                              │        ASEP          │
                              │ Controller /         │
                              │ Orchestrator         │
                              └──────────┬───────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
              ▼                          ▼                          ▼
      ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
      │   METASPLOIT    │        │   WIFI ATTACK   │        │  PERSISTENCE    │
      │   SPECIALIST    │        │   SPECIALIST    │        │   SPECIALIST    │
      └────────┬────────┘        └────────┬────────┘        └────────┬────────┘
               │                          │                          │
               └──────────────────────────┼──────────────────────────┘
                                          │
                                          ▼
                                 ┌──────────────────┐
                                 │    COLLECTION    │
                                 │    SPECIALIST    │
                                 │ Traffic / MITM / │
                                 │ Packet Analysis  │
                                 └────────┬─────────┘
                                          │
                                          ▼
                                Structured Evidence
                                          │
                                          ▼
                              ┌──────────────────────┐
                              │        ASEP          │
                              │ World State          │
                              │ Evidence             │
                              │ Reasoning State      │
                              │ Learning             │
                              │ Replanning           │
                              └──────────────────────┘
```

The diagram is conceptual. Specialist Domains are not required to map one-to-one to a single application or executable.

## 3. Architectural Layers

### 3.1 ASEP Controller

ASEP remains the central controller and orchestrator.

Responsibilities include:

- mission/objective management
- world-state management
- reasoning and replanning
- capability selection
- specialist selection
- cross-specialist coordination
- evidence integration
- outcome reconciliation
- learning
- auditability
- decision-control integration

ASEP should not need to contain every domain-specific implementation detail.

### 3.2 Specialist Domain

A Specialist Domain is a bounded area of technical expertise.

A specialist owns the domain logic needed to answer questions such as:

- What capability is required?
- What prerequisites are needed?
- Which skills can perform the task?
- Which tools can execute those skills?
- What evidence should be collected?
- How is the result validated?
- What alternative methods exist when a method is unavailable or unsuccessful?

A Specialist Domain may use multiple tools and multiple skills.

### 3.3 Skill / Capability

A Skill is an executable or reasoning capability within a specialist domain.

Examples:

- packet capture
- traffic interception assessment
- service enumeration
- vulnerability correlation
- wireless discovery
- exploit candidate validation
- session analysis

Skills are not tied permanently to one tool.

### 3.4 Tool

A Tool is an executor selected by a specialist through the capability/skill layer.

Therefore:

```text
Specialist Domain
      ↓
Capability / Skill
      ↓
Tool / Executor
      ↓
Observation
      ↓
Evidence
      ↓
ASEP
```

A tool may be replaced without changing the specialist's conceptual responsibility.

## 4. Initial Specialist Domains

The following domains are recognized as architectural examples. The catalogue can expand without changing the central ASEP model.

### Metasploit Specialist

Responsible for Metasploit-specific assessment capabilities, including:

- module discovery
- candidate correlation
- prerequisite/evidence review
- CHECK handling
- execution workflow integration
- session-related intelligence

The existing CHECK → approval → RUN semantics remain authoritative.

### WiFi Attack Specialist

Responsible for wireless-security assessment capabilities, including:

- wireless discovery
- wireless protocol assessment
- client/AP observation
- authentication/security assessment
- wireless-specific evidence

### Persistence Specialist

Responsible for authorized persistence-assessment capabilities and their evidence, validation, and lifecycle analysis.

### Collection Specialist

**Formal domain name: Traffic Collection & Interception Assessment**

Responsible for capabilities involving authorized network traffic observation, collection, interception assessment, packet capture, and protocol analysis.

Example tooling/capabilities include:

- Ettercap
- MITM tooling
- ssldump
- Wireshark / tshark
- tcpdump
- packet capture
- protocol inspection
- traffic analysis
- session/traffic evidence extraction

Collection is therefore a **Specialist Domain**, not merely a storage or aggregation component.

## 5. Cross-Specialist Intelligence

Specialists remain separated by responsibility, but their results must be consumable by ASEP.

Example:

```text
WiFi Specialist
      ↓
network/client evidence
      ↓
ASEP World State
      ↓
Collection Specialist
      ↓
traffic evidence
      ↓
ASEP Reasoning State
      ↓
another relevant Specialist
```

This enables ASEP to combine evidence from different domains without forcing those domains to contain each other's implementation logic.

## 6. Standard Specialist Contract

Future Specialist implementations should expose a common conceptual contract:

```text
INPUT
  Mission Objective
  Target / Context
  World State
  Evidence
  Constraints
  Required Capability
        ↓
SPECIALIST
  Analyze
  Select Skill
  Select/resolve Tool
  Execute authorized capability
  Validate result
  Produce evidence
        ↓
OUTPUT
  Observation
  Evidence
  Finding / Candidate
  Outcome
  Confidence
  Failure reason (if applicable)
  Alternative capability candidates
  Replanning signals
```

The exact runtime API is intentionally deferred until the Main Plan is complete and the implementation design is approved.

## 7. Alternative Capability Resolution

A specialist should not be conceptually bound to a single executable.

When a required capability cannot be performed by the preferred tool:

```text
Objective
   ↓
Capability Required
   ↓
Preferred Skill / Tool
   ↓
Unavailable / Failed
   ↓
Specialist evaluates alternatives
   ↓
Alternative Skill / Tool
   ↓
Validate
   ↓
Evidence
   ↓
ASEP Replanning
```

This supports the ASEP principle:

> **Path is replaceable. Objective is persistent.**

Alternative selection must remain evidence-driven and auditable.

## 8. Specialist Registry — Future Direction

The future Specialist Registry should be capable of describing:

- specialist_id
- name
- domain
- objectives supported
- capabilities
- skills
- prerequisites
- candidate tools
- input contract
- output contract
- evidence contract
- validation methods
- alternative skills
- dependencies
- version
- status
- health
- provenance

This registry is a future implementation concern, not an implicit activation of new runtime behavior in the current Main Plan.

## 9. Relationship to the Master Skill Catalogue

The Specialist Domain Architecture extends the previously defined Master Skill Catalogue.

The hierarchy is:

```text
OBJECTIVE
   ↓
CAPABILITY NEEDED
   ↓
SPECIALIST DOMAIN
   ↓
SKILL
   ↓
TOOL / EXECUTOR
   ↓
EVIDENCE
   ↓
ASEP WORLD STATE
   ↓
REASONING / LEARNING / REPLANNING
```

The Master Catalogue therefore remains broader than the currently installed tools.

The architecture is not limited to Kali-installed tools. A specialist may eventually use:

- installed tools
- discoverable external tools
- composed capabilities
- plugins/integrations
- ASEP-created skills
- future ASEP-created tools

Capability evolution remains subject to its separately defined lifecycle and is not activated merely by this architecture document.

## 10. Main Plan Boundary

This architecture is recorded now so that future implementation follows a stable design.

It does **not**:

- declare the Main Plan complete
- start the Evolution Roadmap
- activate self-created skills
- introduce unrestricted new execution paths
- replace existing Decision Control
- bypass existing scope/CHECK/approval requirements
- require immediate UI redesign

The current Main Plan remains governed by its existing completion gate, including the remaining migration/schema-version/restore framework work.

## 11. Design Principle

The final architectural relationship is:

```text
                    ┌─────────────────────────┐
                    │          ASEP           │
                    │ Mission + Reasoning +   │
                    │ World State + Control   │
                    └────────────┬────────────┘
                                 │
                      Specialist Selection
                                 │
             ┌───────────────────┼───────────────────┐
             ▼                   ▼                   ▼
        Specialist A        Specialist B        Specialist C
             │                   │                   │
          Skills              Skills              Skills
             │                   │                   │
           Tools              Tools              Tools
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                         Evidence / Outcomes
                                 │
                                 ▼
                              ASEP Core
                                 │
                         Learn / Replan
                                 │
                                 └──────────────► next action
```

**Architectural statement:**

> **ASEP owns the mission. Specialists own domain expertise. Skills provide capabilities. Tools execute them. Evidence returns to ASEP. ASEP integrates the resulting intelligence and determines the next step.**


## 12. Agentic AI Runtime — Provider-Agnostic Specialist Agents

Specialist Domains are intended to be powered by **agentic AI runtimes**, but a Specialist Agent must never be defined as belonging to a single AI provider.

The architectural rule is:

> **Agent identity belongs to ASEP. The AI provider is an interchangeable runtime resource.**

Therefore the Specialist Agent definition contains its:

- identity
- domain
- mission/capability contract
- skills
- tools
- evidence contract
- memory/state interface
- planning/replanning interface
- validation contract

It does **not** contain a permanent dependency on Claude, OpenAI, Gemini, Ollama, or another provider.

### 12.1 Provider-Neutral Agent Layer

```text
                    ASEP
                     │
              Agent Orchestrator
                     │
             Specialist Agent
                     │
          Agent Runtime Interface
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   Claude Code     OpenAI       Local LLM
        │            │            │
        └────────────┼────────────┘
                     │
             Agent Result / State
                     │
                     ▼
                    ASEP
```

The Specialist Agent therefore depends on an **Agent Runtime Interface**, not directly on a provider SDK.

### 12.2 Multiple Agent Runtimes

ASEP should be able to use different agent runtimes for different specialist domains or tasks.

Examples:

- Claude Code / Claude-based runtime
- OpenAI/Codex-based runtime
- Gemini-based runtime
- local agent runtime
- open-source/self-hosted agent runtime
- future agent runtimes discovered or added later

The architecture must also support multiple runtimes simultaneously.

For example:

```text
MISSION
  │
  ▼
ASEP ORCHESTRATOR
  │
  ├── Metasploit Specialist
  │      └── Agent Runtime A
  │
  ├── WiFi Specialist
  │      └── Agent Runtime B
  │
  ├── Collection Specialist
  │      └── Local Agent Runtime
  │
  └── Persistence Specialist
         └── Agent Runtime C
```

The specialist definition remains unchanged if its underlying runtime changes.

### 12.3 Agent Runtime Selection

Agent selection should be resolved dynamically from capability and runtime metadata rather than hardcoded provider preference.

Conceptually:

```text
OBJECTIVE
   ↓
CAPABILITY
   ↓
SPECIALIST DOMAIN
   ↓
AGENT REQUIREMENTS
   │
   ├─ reasoning complexity
   ├─ tool requirements
   ├─ context requirements
   ├─ latency requirements
   ├─ local/offline requirement
   ├─ data handling requirement
   └─ runtime availability
   ↓
AGENT RUNTIME ROUTER
   ↓
Candidate Runtime(s)
   ↓
Select / Fallback / Parallelize
   ↓
SPECIALIST AGENT
   ↓
Evidence / Outcome
   ↓
ASEP
```

The router may select one runtime, use a fallback, or invoke multiple specialist runtimes when the task benefits from independent reasoning.

### 12.4 No Single Provider as the Brain

ASEP must not become:

```text
ASEP = Claude Agent
```

or:

```text
ASEP = OpenAI Agent
```

Instead:

```text
ASEP
 ├── Mission
 ├── World State
 ├── Reasoning State
 ├── Memory
 ├── Evidence
 ├── Skill Registry
 ├── Specialist Registry
 ├── Agent Runtime Registry
 ├── Orchestrator
 └── Provider / Runtime Adapters
```

This preserves the principle:

> **ASEP has AI — an AI/provider does not own ASEP.**

### 12.5 Agent Runtime Registry

A future Agent Runtime Registry should describe:

- runtime_id
- runtime_name
- provider
- model(s)
- runtime_type
- supported protocols
- supported capabilities
- tool/MCP interfaces
- context limits
- local/cloud status
- availability/health
- latency characteristics
- cost metadata where applicable
- fallback runtimes
- version
- provenance
- health history

The Specialist Agent refers to runtime capabilities rather than vendor identity.

### 12.6 Agent Runtime Failover

Provider/runtime failure must not automatically terminate the Specialist Domain's reasoning.

```text
SPECIALIST TASK
      ↓
PRIMARY RUNTIME
      ↓
failure / unavailable / degraded
      ↓
RUNTIME ROUTER
      ↓
ALTERNATIVE RUNTIME
      ↓
RESUME FROM PERSISTED AGENT STATE
      ↓
SPECIALIST RESULT
      ↓
ASEP
```

The persisted state must allow a runtime switch without losing:

- mission context
- specialist context
- hypothesis
- plan
- task state
- evidence
- previous outcomes
- failed approaches
- replanning state

### 12.7 Runtime Independence

Agent prompts, specialist contracts, mission state, evidence schemas, and ASEP reasoning state must remain provider-neutral.

Provider-specific adaptation belongs only in the adapter/runtime layer.

```text
SPECIALIST LOGIC
      │
      ├── provider-neutral
      │
      ▼
AGENT RUNTIME INTERFACE
      │
      ├── Claude adapter
      ├── OpenAI adapter
      ├── Gemini adapter
      ├── Local adapter
      └── Future adapters
```

Changing an AI provider should therefore be a configuration/runtime change, not a rewrite of the Specialist Domain.

### 12.8 Agentic Specialist Collaboration

Specialists may delegate subtasks to other specialists through ASEP rather than directly coupling themselves to another provider.

```text
Collection Specialist
        │
        │ request capability
        ▼
       ASEP
        │
        ▼
WiFi Specialist
        │
        ▼
Agent Runtime selected independently
        │
        ▼
Evidence
        │
        ▼
ASEP World State
        │
        ▼
Collection Specialist continues
```

This keeps specialist-to-specialist collaboration provider-neutral and centrally observable.

### 12.9 Current Main Plan Boundary

This section records the target architecture only.

It does **not** yet implement:

- Agent Runtime Registry
- provider failover
- multi-agent parallel execution
- autonomous specialist creation
- runtime migration
- new specialist execution paths

Those implementation items remain future roadmap work and must not be used to declare the current Main Plan complete.

The current Main Plan completion gate remains the migration/schema-version/restore framework.

