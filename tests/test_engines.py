import unittest, sys, types, importlib.util
from pathlib import Path
ROOT=Path(__file__).parents[1]
pkg=types.ModuleType('app'); pkg.__path__=[str(ROOT/'app')]; sys.modules['app']=pkg

def load(name):
    spec=importlib.util.spec_from_file_location('app.'+name, ROOT/'app'/f'{name}.py')
    mod=importlib.util.module_from_spec(spec); sys.modules['app.'+name]=mod; spec.loader.exec_module(mod); return mod
wf=load('scope'); win=load('windows_fingerprint'); msf=load('metasploit')
WINDOWS_XML='''<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/><hostnames><hostname name="WIN-CLIENT01"/></hostnames><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Microsoft Windows" version="10"/><script id="smb2-security-mode"><table><elem key="message signing enabled">true</elem><elem key="message signing required">false</elem></table></script></port><port protocol="tcp" portid="135"><state state="open"/><service name="msrpc"/></port><port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port></ports><os><osmatch name="Microsoft Windows 10" accuracy="95"/></os><hostscript><script id="smb-os-discovery"><table><elem key="Computer name">WIN-CLIENT01</elem><elem key="Domain name">LAB.LOCAL</elem><elem key="Workgroup">WORKGROUP</elem></table></script><script id="smb2-security-mode"><table><elem key="message signing enabled">true</elem><elem key="message signing required">false</elem></table></script></hostscript></host></nmaprun>'''
class EngineTests(unittest.TestCase):
 def test_windows_hostscript_identity(self):
  r=win._parse(WINDOWS_XML); self.assertEqual(r['hostname'],'WIN-CLIENT01'); self.assertEqual(r['domain'],'LAB.LOCAL'); self.assertEqual(r['workgroup'],'WORKGROUP'); self.assertEqual(r['smb_signing'],'enabled'); self.assertIn('445',r['services']['smb']); self.assertIn('135',r['services']['rpc']); self.assertIn('3389',r['services']['rdp'])
 def test_smb_required(self):
  self.assertEqual(win._parse(WINDOWS_XML.replace('message signing required">false','message signing required">true'))['smb_signing'],'required')
 def test_msf_negative_before_positive(self):
  self.assertEqual(msf._classify_check('Check result: The target is not vulnerable.',0),'NOT_VULNERABLE'); self.assertEqual(msf._classify_check('Check result: The target is vulnerable.',0),'VULNERABLE'); self.assertEqual(msf._classify_check('Check result: Cannot determine.',0),'UNKNOWN')
if __name__=='__main__': unittest.main()

class FakeStdin:
    def __init__(self): self.writes=[]
    def write(self,s): self.writes.append(s)
    def flush(self): pass
class FakeProc:
    def __init__(self): self.pid=4242; self.stdin=FakeStdin(); self.rc=None
    def poll(self): return self.rc

class PersistenceTests(unittest.TestCase):
    def test_controller_registry_keeps_process_reference(self):
        import tempfile, os
        old_which=msf.shutil.which; old_popen=msf.subprocess.Popen; old_options=msf.module_options
        class FakeOpenLog:
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def write(self,*a): pass
            def flush(self): pass
        try:
            msf.shutil.which=lambda x: '/usr/bin/'+x
            msf.module_options=lambda cfg,module: {'module':module,'options':['RHOSTS','RPORT']}
            fake=FakeProc(); msf.subprocess.Popen=lambda *a,**k: fake
            cfg={'scope':{'scope':{'networks':['192.168.1.0/24'],'hosts':[]}}}
            r=msf.run_module(cfg,'192.168.1.10','exploit/test/module','192.168.1.5',4444)
            self.assertEqual(r['status'],'STARTED')
            self.assertIn(r['session_controller'],msf._PROCS)
            self.assertEqual(msf._PROCS[r['session_controller']],fake)
        finally:
            msf.shutil.which=old_which; msf.subprocess.Popen=old_popen; msf.module_options=old_options

class SessionValidationTests(unittest.TestCase):
 def test_remote_session_id_validation(self):
  self.assertEqual(msf._validate_remote_session_id('12'),'12')
  with self.assertRaises(msf.MetasploitError): msf._validate_remote_session_id('12; sessions -l')
 def test_command_length(self):
  self.assertRaises(msf.MetasploitError, msf.interact_session, 'missing','1','x'*2001)
