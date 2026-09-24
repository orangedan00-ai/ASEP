# ASEP v2.9.7 — Continuous Network Awareness

## Purpose
ASEP continuously maintains an evidence-backed view of the currently connected
local network while keeping dashboard/resource overhead low.

## Dashboard defaults
- Dashboard refresh: 30 seconds
- Resource telemetry: 10 seconds
- Network discovery minimum interval: 30 seconds
- Automatically detect the active local IPv4 network; do not require manual CIDR changes when the laptop moves to another directly connected environment.

## Automatic workflow
Dashboard open
-> environment detection
-> authorized/local-scope determination
-> lightweight host discovery
-> live asset inventory update
-> new/changed/offline host detection
-> queued service discovery for newly observed hosts
-> evidence persistence
-> intelligence/readiness update

## Dashboard information
Keep the main dashboard clean. Show only:
- current network/CIDR
- local IP
- default gateway
- DNS servers
- interface
- live hosts
- assets
- observed services
- findings
- attack paths
- lightweight CPU/RAM/disk/network telemetry
- concise new-device/status indicator

Detailed data remains available from Targets, Network Discovery, Evidence,
Intelligence, and Target Detail.

## Accuracy rules
- A live host is not automatically a vulnerability.
- MAC/OUI identifies a vendor when supported; it does not by itself prove
  device form factor or network role.
- Device type/role must be evidence-correlated and carry confidence/basis.
- Logical topology must not be presented as physical topology unless proven.
- Preserve discovery timestamps and evidence provenance.
- Detect IP/MAC identity changes.
- Keep offline historical assets without counting them as currently live.

## Automatic service discovery
New hosts may be queued for service discovery, but execution must be
resource-controlled rather than launching an unrestricted parallel scan.
Service results must remain evidence-backed and feed the normal:
IDENTIFY -> SERVICES -> ANALYZE -> VALIDATE workflow.

## Scope safety
Automatic environment adaptation follows the directly connected local network
on the active interface. It must not silently expand into arbitrary remote,
routed, or unrelated networks. Active testing outside the established/authorized
scope requires explicit authorization.

## Resource policy
Resource telemetry must be lightweight and periodic. Network discovery has a
minimum 30-second interval and must not be triggered repeatedly merely because
the browser is refreshed.

## Attack Graph
Use an adaptive, readable layout for large inventories:
- grid/cluster layout
- viewport scrolling/zooming where available
- avoid overlapping nodes
- stable placement between refreshes when possible
- clickable assets
- evidence-backed logical relationships

## Dashboard presentation
The main Dashboard always exposes the current network identity and a compact live-host inventory. Detailed target pages remain for deeper evidence, service details and validation. The Asset Graph uses a scrollable adaptive grid for large inventories rather than clipping nodes.

- Previously known hosts not seen in the current discovery cycle are marked offline while retaining first/last-seen history.
- An IP/MAC identity change is treated as a new asset observation and triggers service discovery.

## Comprehensive Network Scan (v2.9.9)

After automatic discovery has populated the live-host inventory, use **FULL NETWORK SCAN** on the Dashboard to perform an explicit comprehensive inventory scan against the currently live hosts on the directly connected local network. It checks TCP ports 1–65535 and performs Nmap service/version detection. UDP is not scanned. This can be resource- and time-intensive, so it is operator-triggered rather than part of the continuous 30-second awareness loop.

Results are persisted as `deep_service_scan` evidence and replace/enrich the target port/service inventory. The dashboard then shows the observed open ports and identified services. A port being open or a service being identified is observation/evidence, not a vulnerability finding.

## v2.9.12 Comprehensive Service Inventory & Environment Lifecycle
- Automatic comprehensive scan starts after live-host discovery.
- TCP 1–65535 with full service/version probes; UDP is not scanned.
- New local hosts are queued; already-scanned hosts are not rescanned every 30 seconds.
- Dashboard refreshes after completion.
- Manual RESCAN ALL SERVICES forces a fresh TCP batch.
- On a new laptop boot, network-derived inventory is cleared before the new environment is discovered.
