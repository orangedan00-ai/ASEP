# ASEP v2.9.5 Identity, Role & Topology

ASEP enriches each active host using multiple local evidence sources: Nmap OUI data, arp-scan/IEEE data when installed, system reverse DNS/getent, MAC flags, observed services, local routing and ARP neighbor state. IEEE registration data identifies assigned organizations/OUI blocks; it does not prove the physical form factor of a device.

Logical role is inferred from routing, hostname, vendor and observed services. It is explicitly labeled with confidence and basis.

Dashboard Asset Graph is a logical topology view: gateway relationships are derived from the local default route; LAN-neighbor relationships are derived from the local ARP neighbor table. This does not claim physical switch/AP topology.

Target detail shows identity sources, inferred role, topology context, observed services and linked evidence. If no service evidence exists, the user can explicitly start service validation from the target window.
