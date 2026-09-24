import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.identity_enrichment import normalize_mac, mac_flags, lookup_vendor, lookup_vendor_sources, enrich_identity, infer_network_role, infer_asset_type


class IdentityEnrichmentTest(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(normalize_mac('00:09:0F:AA:BB:CC'), '00:09:0F:AA:BB:CC')
        self.assertEqual(normalize_mac('00090FAABBCC'), '00:09:0F:AA:BB:CC')

    def test_locally_administered_is_not_claimed_as_vendor(self):
        flags = mac_flags('02:11:22:33:44:55')
        self.assertTrue(flags['locally_administered'])
        self.assertTrue(flags['randomized'])
        vendor, source = lookup_vendor('02:11:22:33:44:55')
        self.assertEqual(source, 'LOCAL_ADMIN')
        self.assertIn('Randomized', vendor)

    def test_local_nmap_vendor_registry(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / 'nmap-mac-prefixes'
            f.write_text('00090F Fortinet\n')
            with patch('app.identity_enrichment._VENDOR_FILES', (f,)):
                vendor, source = lookup_vendor('00:09:0F:AA:BB:CC')
        self.assertEqual(vendor, 'Fortinet')
        self.assertEqual(source, 'LOCAL_REGISTRY')

    def test_multiple_vendor_sources_are_exposed(self):
        with tempfile.TemporaryDirectory() as td:
            f1 = Path(td) / 'nmap-mac-prefixes'
            f2 = Path(td) / 'oui.txt'
            f1.write_text('00090F Fortinet\n')
            f2.write_text('00090F Fortinet Inc.\n')
            with patch('app.identity_enrichment._VENDOR_FILES', (f1, f2, Path(td)/'missing')):
                sources = lookup_vendor_sources('00:09:0F:AA:BB:CC')
        self.assertEqual(len(sources), 2)
        self.assertTrue(all(x['status']=='MATCH' for x in sources))

    def test_gateway_role_uses_routing_evidence(self):
        r = infer_network_role('192.168.1.1', 'router', 'MikroTik', [], '192.168.1.1')
        self.assertEqual(r['role'], 'Gateway / Router')
        self.assertEqual(r['confidence'], 'high')

    def test_enrichment_prefers_nmap_values(self):
        with patch('app.identity_enrichment.reverse_hostname', return_value=('', 'NOT_FOUND')), patch('app.identity_enrichment.lookup_vendor', return_value=('', 'NOT_FOUND')):
            result = enrich_identity('192.168.1.2', '00:09:0F:AA:BB:CC', 'host01', 'Vendor Inc')
        self.assertEqual(result['hostname'], 'host01')
        self.assertEqual(result['vendor'], 'Vendor Inc')
        self.assertEqual(result['hostname_source'], 'NMAP')
        self.assertEqual(result['vendor_source'], 'NMAP_OUI')


    def test_hostname_iphone_pattern_detected_as_mobile_medium_confidence(self):
        result = infer_asset_type(vendor="Apple, Inc.", hostname="Johns-iPhone")
        self.assertEqual(result["type"], "Mobile Phone")
        self.assertEqual(result["confidence"], "medium")
        self.assertEqual(result["brand"], "Apple (iPhone)")

    def test_hostname_android_generic_pattern_detected(self):
        result = infer_asset_type(vendor="Google Inc.", hostname="android-a1b2c3d4")
        self.assertEqual(result["type"], "Mobile Phone")
        self.assertEqual(result["confidence"], "medium")

    def test_hostname_galaxy_pattern_infers_samsung_brand(self):
        result = infer_asset_type(vendor="", hostname="Galaxy-S21")
        self.assertEqual(result["type"], "Mobile Phone")
        self.assertEqual(result["brand"], "Samsung")

    def test_vendor_only_phone_brand_is_low_confidence_and_caveated(self):
        result = infer_asset_type(vendor="Samsung Electronics Co.,Ltd", hostname="")
        self.assertEqual(result["type"], "Mobile Phone")
        self.assertEqual(result["confidence"], "low")
        self.assertEqual(result["brand"], "Samsung")
        self.assertIn("also makes non-phone devices", result["basis"])

    def test_bare_apple_vendor_without_phone_hostname_is_not_claimed_as_phone(self):
        # Apple is deliberately excluded from the vendor-only phone bucket
        # (MacBooks, Apple TVs, etc. share the same OUI) -- must not
        # regress into a false "Mobile Phone" claim without a hostname hint.
        result = infer_asset_type(vendor="Apple, Inc.", hostname="")
        self.assertNotEqual(result["type"], "Mobile Phone")

    def test_macbook_hostname_still_classified_as_laptop_not_phone(self):
        result = infer_asset_type(vendor="Apple, Inc.", hostname="Johns-MacBook-Pro")
        self.assertEqual(result["type"], "Laptop / Endpoint")


if __name__ == '__main__':
    unittest.main()
