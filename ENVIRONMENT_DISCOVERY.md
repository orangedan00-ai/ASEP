# ASEP v2.9.4 — Environment Awareness & Active Host Inventory

ASEP can now operate across changing lab environments without requiring a
pre-known CIDR.

## Flow

```text
Detect local interface(s)
        ↓
Detect local IPv4 network candidate(s)
        ↓
User confirms candidate
        ↓
Host discovery only (-sn)
        ↓
Active Host Inventory
        ↓
Persist target records + evidence
        ↓
Optional later service analysis
```

### Passive phase
`GET /api/environment` detects local IPv4 addresses, interfaces, gateways and
connected network candidates. This phase sends no discovery probes.

### Active phase
`POST /api/network-discovery/start` accepts a locally detected candidate and
requires `confirm_local_scope=true`. The backend re-checks that the requested
CIDR is currently attached to a local IPv4 interface before launching Nmap.

Methods:

- `auto` — Nmap host discovery defaults; on local Ethernet/Wi-Fi Nmap uses ARP
  discovery where applicable.
- `arp` — `-sn -PR`
- `icmp` — `-sn -PE -PP`
- `tcp` — `-sn -PS80,443 -PA80`

The discovery stage does **not** run a service scan. Active hosts are persisted
in the ASEP target inventory and linked to evidence and discovery history.

## Scope behavior

A detected network that is not already listed in `config/scope.yaml` is marked
`LOCAL-CANDIDATE`, not automatically converted into permanent scope. This
allows ASEP to discover the current lab without silently expanding the normal
assessment scope.

For service scans, vulnerability validation, exploitation and other normal
assessment actions, the normal explicit scope controls remain in force.

## API

- `GET /api/environment`
- `POST /api/network-discovery/start`
- `GET /api/network-discovery/status`
- `GET /api/network-discovery/history`
- `GET /api/v2/environment`
- `GET /api/v2/discovery-history`

Nmap host discovery reference: https://nmap.org/book/man-host-discovery.html
