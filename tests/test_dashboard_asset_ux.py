import tempfile
import unittest
from pathlib import Path

from app.config import load_config
from app.db import init_db, upsert_target, add_evidence
from app.identity_enrichment import infer_asset_type, infer_network_role
from app.ux import intelligence_summary

class DashboardAssetUXTests(unittest.TestCase):
    def test_firewall_inference(self):
        r = infer_asset_type('Fortinet', 'fw01', 'unknown', [])
        self.assertEqual(r['type'], 'Firewall')

    def test_gateway_inference(self):
        r = infer_asset_type('MikroTik', 'gateway', 'router', [])
        self.assertEqual(r['type'], 'Router / Gateway')

    def test_printer_inference(self):
        r = infer_asset_type('HP', 'office-printer', 'unknown', [{'port':'9100'}])
        self.assertEqual(r['type'], 'Printer')

    def test_role_is_not_claimed_from_mac_alone(self):
        r = infer_network_role('192.168.1.25', '', 'Lenovo', [], '192.168.1.1')
        self.assertEqual(r['role'], 'Unknown')
        self.assertEqual(r['confidence'], 'low')

    def test_endpoint_does_not_claim_form_factor_from_mac_alone(self):
        r = infer_asset_type('Lenovo', '', 'unknown', [])
        self.assertIn('Endpoint', r['type'])
        self.assertEqual(r['confidence'], 'low')

    def test_intelligence_summary_reports_readiness_and_gaps(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = load_config(); cfg.update({'root': td, 'data_root': td})
            init_db(cfg)
            upsert_target(cfg, {'address':'192.168.1.10','name':'host10','role':'unknown','state':'up','scope_status':'IN-SCOPE','mac':'AA:BB:CC:00:00:01','vendor':'ExampleVendor','source':'test','metadata':{'ports':[]}})
            upsert_target(cfg, {'address':'192.168.1.11','name':'','role':'unknown','state':'up','scope_status':'IN-SCOPE','mac':'','vendor':'','source':'test','metadata':{'ports':[]}})
            add_evidence(cfg, 'nmap', '192.168.1.10', 'service scan', '{"status":"OBSERVED"}')
            d = intelligence_summary(cfg, {'network':'192.168.1.0/24'}, {'paths':[], 'findings':[]})
            self.assertEqual(d['summary']['active_hosts'], 2)
            self.assertEqual(d['summary']['identified_hosts'], 1)
            self.assertTrue(any(x['id']=='identity' and x['status']=='NEEDS_MORE_EVIDENCE' for x in d['readiness']))
            self.assertEqual(d['next_best_action']['action'], 'identity')

if __name__ == '__main__':
    unittest.main()
