import unittest
from unittest.mock import patch
from app import metasploit

class MetasploitRemoteCandidateTests(unittest.TestCase):
    def test_local_priv_esc_is_rejected(self):
        with self.assertRaises(metasploit.MetasploitError):
            metasploit._remote_target_option({}, 'exploit/linux/local/abrt_raceabrt_priv_esc')

    def test_check_uses_rhost_when_module_does_not_have_rhosts(self):
        with patch.object(metasploit, '_require'), patch.object(
            metasploit, 'module_options', return_value={'options':['RHOST','RPORT']}
        ), patch.object(metasploit, 'assert_target'), patch.object(
            metasploit.subprocess, 'run', return_value=type('P', (), {'stdout':'target is not vulnerable','stderr':'','returncode':0})()
        ) as run:
            result=metasploit.check_module({}, '192.0.2.10', 'exploit/test/remote', rport=8291)
        self.assertEqual(result['target_option'], 'RHOST')
        cmd=' '.join(run.call_args.args[0])
        self.assertIn('set RHOST 192.0.2.10', cmd)
        self.assertIn('set RPORT 8291', cmd)
        self.assertNotIn('set RHOSTS 192.0.2.10', cmd)

    def test_check_rejects_module_without_remote_target_option(self):
        with patch.object(metasploit, '_require'), patch.object(
            metasploit, 'module_options', return_value={'options':['SESSION']}
        ), patch.object(metasploit, 'assert_target'):
            with self.assertRaises(metasploit.MetasploitError):
                metasploit.check_module({}, '192.0.2.10', 'exploit/test/local', rport=80)

if __name__ == '__main__':
    unittest.main()


def test_platform_compatibility_allows_multi_and_rejects_other_os():
    from app.metasploit import _platform_compatible
    assert _platform_compatible('windows', ['multi'])
    assert _platform_compatible('linux', ['linux'])
    assert not _platform_compatible('windows', ['linux'])
