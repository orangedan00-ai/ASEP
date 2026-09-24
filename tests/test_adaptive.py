import unittest
import sys, types, importlib.util
from pathlib import Path
ROOT=Path(__file__).parents[1]
pkg=types.ModuleType('app'); pkg.__path__=[str(ROOT/'app')]; sys.modules['app']=pkg

def load(name):
    spec=importlib.util.spec_from_file_location('app.'+name, ROOT/'app'/f'{name}.py')
    mod=importlib.util.module_from_spec(spec); sys.modules['app.'+name]=mod; spec.loader.exec_module(mod); return mod
adaptive=load('adaptive_reasoning'); deception=load('deception'); skills=load('skill_library')

class AdaptiveTests(unittest.TestCase):
    def test_hypothesis_generation(self):
        r=adaptive.build_hypotheses('192.168.1.10',['Windows host','SMB 445'])
        ids={x['id'] for x in r['hypotheses']}
        self.assertIn('H1',ids); self.assertIn('H2',ids)
    def test_alternative_paths(self):
        r=adaptive.alternative_paths(['A','B','C','D'], [('A','B','smb'),('A','C','web'),('B','D','credential'),('C','D','auth')], 'A')
        self.assertEqual(len(r),2)
    def test_deception_is_uncertain(self):
        r=deception.assess('10.0.0.5',{},['possible decoy'])
        self.assertEqual(r['status'],'HIGH_DECOY_INDICATION')
    def test_skill_inventory(self):
        self.assertIn('adaptive_reasoning', skills.inventory())

if __name__=='__main__': unittest.main()
