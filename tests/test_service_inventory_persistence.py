import json
import tempfile
import unittest
from pathlib import Path

from app.db import init_db, create_service_scan, add_service_inventory, finish_service_scan, list_service_inventory, latest_service_scan, latest_service_scan_xml, reset_network_state, upsert_target

class ServiceInventoryPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        self.cfg={"root":Path(self.td.name), "data_root":Path(self.td.name)}
        init_db(self.cfg)

    def tearDown(self):
        self.td.cleanup()

    def test_deep_service_inventory_persists_and_is_queryable(self):
        scan_id=create_service_scan(self.cfg,"192.168.1.12","192.168.1.0/24","deep_full","automatic",["nmap","-oX","scan.xml","-n","-sT","-p-","-sV","--version-all","--allports","--reason"])
        ports=[{"port":"22","protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"9.6","confidence":"10","cpe":"cpe:/a:openbsd:openssh:9.6","reason":"syn-ack"},{"port":"8080","protocol":"tcp","state":"open","service":"http","product":"Apache httpd","version":"2.4.62","confidence":"10","reason":"syn-ack"}]
        add_service_inventory(self.cfg,scan_id,"192.168.1.12",ports)
        finish_service_scan(self.cfg,scan_id,"COMPLETE",raw_xml='<nmaprun><host><ports/></host></nmaprun>',port_count=2,service_count=2)
        rows=list_service_inventory(self.cfg,"192.168.1.12")
        self.assertEqual([r["port"] for r in rows],[22,8080])
        self.assertEqual(rows[0]["product"],"OpenSSH")
        self.assertEqual(rows[0]["confidence"],10)
        self.assertEqual(latest_service_scan(self.cfg,"192.168.1.12")["status"],"COMPLETE")
        self.assertIn("nmaprun",latest_service_scan_xml(self.cfg,"192.168.1.12"))

    def test_persisted_inventory_is_authoritative_after_target_metadata_is_stale(self):
        upsert_target(self.cfg, {"address":"192.168.1.12","state":"up","metadata":{"ports":[]}})
        scan_id=create_service_scan(self.cfg,"192.168.1.12","192.168.1.0/24","deep_full","automatic",[])
        add_service_inventory(self.cfg,scan_id,"192.168.1.12",[{"port":"22","protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"9.6"}])
        finish_service_scan(self.cfg,scan_id,"COMPLETE",raw_xml='<nmaprun/>',port_count=1,service_count=1)
        rows=list_service_inventory(self.cfg,"192.168.1.12",latest_only=True)
        self.assertEqual(rows[0]["port"],22)
        self.assertEqual(rows[0]["service"],"ssh")

    def test_network_reset_removes_service_inventory(self):
        scan_id=create_service_scan(self.cfg,"10.0.0.5","10.0.0.0/24","deep_full","automatic",[])
        add_service_inventory(self.cfg,scan_id,"10.0.0.5",[{"port":"22","protocol":"tcp","state":"open","service":"ssh"}])
        finish_service_scan(self.cfg,scan_id,"COMPLETE",raw_xml='<nmaprun/>',port_count=1,service_count=1)
        self.assertEqual(len(list_service_inventory(self.cfg,"10.0.0.5")),1)
        reset_network_state(self.cfg)
        self.assertEqual(len(list_service_inventory(self.cfg,"10.0.0.5")),0)

if __name__=="__main__": unittest.main()
