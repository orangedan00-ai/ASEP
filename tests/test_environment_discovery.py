import ipaddress
import unittest
from unittest.mock import patch

from app.network_discovery import _select_candidate, environment_candidates
from app.scope import assert_local_discovery_target, ScopeError
from app.nmap_executor import _parse_xml, PROFILES


class EnvironmentDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "scope": {
                "scope": {"networks": ["192.168.1.0/24"], "hosts": []},
                "environment_discovery": {"enabled": True, "require_confirmation": True},
            }
        }

    def test_select_candidate_requires_detected_local_network(self):
        ctx = {"candidates": [{"network": "10.20.30.0/24", "primary": True}]}
        self.assertEqual(_select_candidate(ctx, "10.20.30.0/24")["network"], "10.20.30.0/24")
        with self.assertRaises(ScopeError):
            _select_candidate(ctx, "10.20.31.0/24")

    def test_environment_detection_is_passive(self):
        fake = {
            "hostname": "kali",
            "gateway": "10.20.30.1",
            "gateway_iface": "eth0",
            "local_ips": [{"ip": "10.20.30.25", "prefix": 24, "network": "10.20.30.0/24", "interface": "eth0", "kind": "ethernet"}],
            "candidates": [{"network": "10.20.30.0/24", "interface": "eth0", "kind": "ethernet", "local_ip": "10.20.30.25", "prefix": 24, "gateway": "10.20.30.1", "primary": True, "source": "local-interface"}],
        }
        with patch("app.network_discovery.local_context", return_value=fake):
            result = environment_candidates(self.cfg)
        self.assertFalse(result["active_probe_sent"])
        self.assertEqual(result["primary"]["network"], "10.20.30.0/24")
        self.assertEqual(result["candidates"][0]["scope_status"], "LOCAL-CANDIDATE")

    def test_local_discovery_scope_rejects_nonlocal_network(self):
        with patch("app.scope._local_ipv4_networks", return_value=[ipaddress.ip_network("10.20.30.0/24")]):
            assert_local_discovery_target(self.cfg, "10.20.30.0/24")
            with self.assertRaises(ScopeError):
                assert_local_discovery_target(self.cfg, "10.20.31.0/24")

    def test_host_discovery_profiles_do_not_enable_service_scan(self):
        for name in ("host_discovery_auto", "host_discovery_arp", "host_discovery_icmp", "host_discovery_tcp"):
            args = PROFILES[name]
            self.assertIn("-sn", args)
            self.assertIn("-R", args)
            self.assertNotIn("-sV", args)
            self.assertNotIn("-p-", args)

    def test_host_discovery_profiles_request_reverse_dns(self):
        for name in ("host_discovery_auto", "host_discovery_arp", "host_discovery_icmp", "host_discovery_tcp"):
            self.assertIn("-R", PROFILES[name])

    def test_nmap_parser_keeps_os_detection(self):
        from app.nmap_executor import _parse_xml
        xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><os><osmatch name="Microsoft Windows 10" accuracy="96"><osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="10" accuracy="96"><cpe>cpe:/o:microsoft:windows_10</cpe></osclass></osmatch></os><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Microsoft Windows" method="probed" conf="10"/></port></ports></host></nmaprun>"""
        host=_parse_xml(xml)[0]
        self.assertEqual(host['os_detection']['matches'][0]['name'], 'Microsoft Windows 10')
        self.assertEqual(host['os_detection']['classes'][0]['osgen'], '10')
        self.assertIn('cpe:/o:microsoft:windows_10', host['os_detection']['cpe'])

    def test_nmap_parser_keeps_service_and_version(self):
        xml = '''<nmaprun><host><status state="up"/><address addr="192.168.1.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port></ports></host></nmaprun>'''
        host = _parse_xml(xml)[0]
        self.assertEqual(host["ports"][0]["service"], "ssh")
        self.assertEqual(host["ports"][0]["version"], "9.2p1")
        self.assertEqual(host["ports"][1]["service"], "http")

    def test_nmap_parser_keeps_mac_vendor(self):
        xml = '''<nmaprun><host><status state="up"/><address addr="10.20.30.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Vendor"/><hostnames><hostname name="server01"/></hostnames></host></nmaprun>'''
        host = _parse_xml(xml)[0]
        self.assertEqual(host["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(host["vendor"], "Example Vendor")
        self.assertEqual(host["hostnames"], ["server01"])

    def test_topology_lan_neighbor_uses_local_ip_and_deduplicates_edges(self):
        from unittest.mock import patch
        import app.network_discovery as nd

        cfg = {"scope": {"scope": {"networks": ["192.168.1.0/24"], "hosts": []}}}
        fake_ctx = {
            "hostname": "asep",
            "gateway": "192.168.1.1",
            "gateway_iface": "eth0",
            "local_ips": [{"ip": "192.168.1.50", "network": "192.168.1.0/24", "interface": "eth0"}],
            "candidates": [{
                "network": "192.168.1.0/24", "interface": "eth0", "kind": "ethernet",
                "local_ip": "192.168.1.50", "prefix": 24, "gateway": "192.168.1.1", "primary": True,
            }],
        }
        fake_nmap = {
            "ok": True,
            "command": ["nmap", "-sn", "192.168.1.0/24"],
            "hosts": [
                {"addresses": ["192.168.1.1"], "hostnames": [], "mac": "AA:AA:AA:AA:AA:01", "vendor": "RouterCo", "state": "up", "ports": []},
                {"addresses": ["192.168.1.20"], "hostnames": [], "mac": "AA:AA:AA:AA:AA:20", "vendor": "HostCo", "state": "up", "ports": []},
                {"addresses": ["192.168.1.50"], "hostnames": [], "mac": "AA:AA:AA:AA:AA:50", "vendor": "ASEPCo", "state": "up", "ports": []},
            ],
        }
        fake_neighbors = [
            {"ip": "192.168.1.20", "mac": "AA:AA:AA:AA:AA:20", "interface": "eth0", "state": "REACHABLE"},
            {"ip": "192.168.1.1", "mac": "AA:AA:AA:AA:AA:01", "interface": "eth0", "state": "REACHABLE"},
        ]
        with patch.object(nd, "local_context", return_value=fake_ctx), \
             patch.object(nd, "run_nmap", return_value=fake_nmap), \
             patch.object(nd, "neighbor_table", return_value=fake_neighbors), \
             patch.object(nd, "enrich_identity", side_effect=lambda ip, mac, hostname, vendor: {
                 "hostname": hostname, "vendor": vendor, "mac_normalized": mac, "vendor_sources": [],
                 "mac_flags": {"randomized": False},
             }), \
             patch.object(nd, "infer_network_role", side_effect=lambda *args, **kwargs: {
                 "role": "Gateway / Router" if args[0] == "192.168.1.1" else "Unknown",
                 "confidence": "high" if args[0] == "192.168.1.1" else "low",
                 "basis": "test",
             }):
            result = nd.discover(cfg, network="192.168.1.0/24", method="auto")

        edges = result["topology"]["edges"]
        self.assertTrue(any("lan-neighbor" in e["relations"] and e["from"] == "192.168.1.50" and e["to"] == "192.168.1.20" for e in edges))
        self.assertFalse(any("lan-neighbor" in e["relations"] and e["from"] == "192.168.1.1" and e["to"] == "192.168.1.20" for e in edges))
        pairs = [(e["from"], e["to"]) for e in edges]
        self.assertEqual(len(pairs), len(set(pairs)))
        gateway_edge = next(e for e in edges if e["from"] == "192.168.1.1" and e["to"] == "192.168.1.20")
        self.assertIn("default-gateway", gateway_edge["relations"])
    def test_discover_returns_structured_error_when_no_local_candidate(self):
        """Regression test: discover() must not raise when no locally
        attached network currently matches the request (e.g. auto-refresh
        firing while the interface is momentarily down/roaming). It must
        return the same {"ok": False, "errors": [...]} contract used for
        run_nmap scope failures, so callers always get a persistable result.
        """
        import app.network_discovery as nd
        empty_ctx = {
            "hostname": "asep", "gateway": None, "gateway_iface": None,
            "local_ips": [], "candidates": [],
        }
        with patch.object(nd, "local_context", return_value=empty_ctx):
            result = nd.discover(self.cfg, network=None, method="auto", interface=None)
        self.assertFalse(result["ok"])
        self.assertEqual(result["active_hosts"], [])
        self.assertTrue(result["errors"])
        self.assertIn("network", result)

    def test_environment_exposes_dns_and_primary_fallback(self):
        import app.network_discovery as nd
        fake = {
            "hostname": "asep", "gateway": None, "gateway_iface": None,
            "local_ips": [{"ip":"10.10.10.25","prefix":24,"network":"10.10.10.0/24","interface":"eth0","kind":"ethernet"}],
            "candidates": [{"network":"10.10.10.0/24","interface":"eth0","kind":"ethernet","local_ip":"10.10.10.25","prefix":24,"gateway":None,"primary":False,"source":"local-interface"}],
        }
        with patch.object(nd, "local_context", return_value=fake), patch.object(nd, "_dns_servers", return_value=["10.10.10.1"]):
            result = nd.environment_candidates(self.cfg)
        self.assertEqual(result["primary"]["network"], "10.10.10.0/24")
        self.assertEqual(result["context"]["local_ip"], "10.10.10.25")
        self.assertEqual(result["context"]["dns_servers"], ["10.10.10.1"])


    def test_diagnostic_flagged_when_zero_hosts_found(self):
        import app.network_discovery as nd
        cfg = {"scope": {"scope": {"networks": ["192.168.1.0/24"], "hosts": []}}}
        fake_ctx = {
            "hostname": "asep", "gateway": "192.168.1.1", "gateway_iface": "eth0",
            "local_ips": [{"ip": "192.168.1.50", "network": "192.168.1.0/24", "interface": "eth0"}],
            "candidates": [{"network": "192.168.1.0/24", "interface": "eth0", "kind": "ethernet",
                             "local_ip": "192.168.1.50", "prefix": 24, "gateway": "192.168.1.1", "primary": True}],
        }
        fake_nmap = {"ok": True, "command": ["nmap"], "hosts": []}
        with patch.object(nd, "local_context", return_value=fake_ctx), \
             patch.object(nd, "run_nmap", return_value=fake_nmap), \
             patch.object(nd, "neighbor_table", return_value=[]):
            result = nd.discover(cfg, network="192.168.1.0/24", method="auto")
        self.assertIsNotNone(result["network_diagnostic"])
        self.assertEqual(result["network_diagnostic"]["level"], "warning")
        self.assertTrue(any("aptive portal" in c for c in result["network_diagnostic"]["likely_causes"]))
        self.assertTrue(any("isolation" in c.lower() for c in result["network_diagnostic"]["likely_causes"]))

    def test_diagnostic_flagged_when_only_gateway_visible(self):
        import app.network_discovery as nd
        cfg = {"scope": {"scope": {"networks": ["192.168.1.0/24"], "hosts": []}}}
        fake_ctx = {
            "hostname": "asep", "gateway": "192.168.1.1", "gateway_iface": "eth0",
            "local_ips": [{"ip": "192.168.1.50", "network": "192.168.1.0/24", "interface": "eth0"}],
            "candidates": [{"network": "192.168.1.0/24", "interface": "eth0", "kind": "ethernet",
                             "local_ip": "192.168.1.50", "prefix": 24, "gateway": "192.168.1.1", "primary": True}],
        }
        fake_nmap = {"ok": True, "command": ["nmap"], "hosts": [
            {"addresses": ["192.168.1.1"], "hostnames": [], "mac": "AA:AA:AA:AA:AA:01", "vendor": "RouterCo", "state": "up", "ports": []},
        ]}
        with patch.object(nd, "local_context", return_value=fake_ctx), \
             patch.object(nd, "run_nmap", return_value=fake_nmap), \
             patch.object(nd, "neighbor_table", return_value=[]), \
             patch.object(nd, "enrich_identity", side_effect=lambda ip, mac, hostname, vendor: {
                 "hostname": hostname, "vendor": vendor, "mac_normalized": mac, "vendor_sources": [], "mac_flags": {"randomized": False}}), \
             patch.object(nd, "infer_network_role", return_value={"role": "Gateway / Router", "confidence": "high", "basis": "test"}):
            result = nd.discover(cfg, network="192.168.1.0/24", method="auto")
        self.assertIsNotNone(result["network_diagnostic"])
        self.assertEqual(result["network_diagnostic"]["level"], "info")
        self.assertTrue(any("isolation" in c.lower() for c in result["network_diagnostic"]["likely_causes"]))

    def test_no_diagnostic_when_other_hosts_are_found(self):
        import app.network_discovery as nd
        cfg = {"scope": {"scope": {"networks": ["192.168.1.0/24"], "hosts": []}}}
        fake_ctx = {
            "hostname": "asep", "gateway": "192.168.1.1", "gateway_iface": "eth0",
            "local_ips": [{"ip": "192.168.1.50", "network": "192.168.1.0/24", "interface": "eth0"}],
            "candidates": [{"network": "192.168.1.0/24", "interface": "eth0", "kind": "ethernet",
                             "local_ip": "192.168.1.50", "prefix": 24, "gateway": "192.168.1.1", "primary": True}],
        }
        fake_nmap = {"ok": True, "command": ["nmap"], "hosts": [
            {"addresses": ["192.168.1.1"], "hostnames": [], "mac": "AA:AA:AA:AA:AA:01", "vendor": "RouterCo", "state": "up", "ports": []},
            {"addresses": ["192.168.1.20"], "hostnames": [], "mac": "AA:AA:AA:AA:AA:20", "vendor": "HostCo", "state": "up", "ports": []},
        ]}
        with patch.object(nd, "local_context", return_value=fake_ctx), \
             patch.object(nd, "run_nmap", return_value=fake_nmap), \
             patch.object(nd, "neighbor_table", return_value=[]), \
             patch.object(nd, "enrich_identity", side_effect=lambda ip, mac, hostname, vendor: {
                 "hostname": hostname, "vendor": vendor, "mac_normalized": mac, "vendor_sources": [], "mac_flags": {"randomized": False}}), \
             patch.object(nd, "infer_network_role", side_effect=lambda *a, **k: {
                 "role": "Gateway / Router" if a[0] == "192.168.1.1" else "Unknown", "confidence": "high", "basis": "test"}):
            result = nd.discover(cfg, network="192.168.1.0/24", method="auto")
        self.assertIsNone(result["network_diagnostic"])


if __name__ == "__main__":
    unittest.main()
