# ASEP Network Environment Lifecycle

ASEP runs as a portable network-security workstation. Network-derived inventory must not leak from one laptop boot or DHCP environment into the next.

## Cleanup boundary

Cleared on a new environment:
- discovered targets
- service/port evidence
- discovery-run history

Preserved:
- audit history
- scope/configuration
- skills
- application source

## Environment identity

ASEP records:
- Linux boot ID
- primary IPv4 network/CIDR
- interface
- interface kind
- local IPv4 address
- default gateway

A new OS boot triggers cleanup even when DHCP assigns the same address. A changed network identity (for example a new DHCP address/network) also triggers cleanup when the lifecycle marker is compared.

## Result

After restart, ASEP starts network discovery from the currently assigned environment instead of reusing stale IP/service data from the previous connection.

## Operator note — restart between networks/engagements

Cleanup (`prepare_environment_state()`) only runs once, at process start (`app/__init__.py::main()`). It is **not** re-checked while ASEP keeps running.

This has a practical consequence: if you move to a different network *without restarting ASEP*, discovery still adapts correctly to the new network — the continuous-awareness loop re-detects the new primary interface/subnet every cycle and starts discovering hosts there. But targets discovered on the *previous* network are not purged or marked offline (the offline-marking pass only evaluates hosts inside the network CIDR that was just scanned), so they remain in the inventory at their last known state until the next restart.

**Decision (confirmed by operator, 2026-09-22): keep this behavior as designed (no runtime auto-reset).** Operational rule: restart ASEP every time you move to a different network, lab, or engagement, so the environment-identity check clears the previous network's inventory/evidence before the next assessment begins. Do not rely on ASEP to self-clean mid-session across networks.
