# ASEP v2.9.5 Release

ASEP v2.9.5 adds Environment Awareness and Active Host Inventory on top of the validated v2.8.2 core and v2.9 UX architecture.

## Validation target

- 25 unit/integration tests pass in the build environment
- Route contract passes
- JavaScript syntax check passes
- Runtime smoke requires Flask and is executed when Flask is installed
- Release archive excludes Python caches

## Main changes

- Detect connected local IPv4 network candidates without prior CIDR knowledge.
- Require explicit confirmation before active host discovery.
- Discover hosts using Nmap `-sn` profiles only.
- Persist active hosts and discovery history.
- Show new/known host counts.
- Keep detected-but-not-configured networks as `LOCAL-CANDIDATE`.
- Keep normal service scanning, validation and exploitation scope enforcement unchanged.
