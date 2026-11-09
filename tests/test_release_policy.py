import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('policy',ROOT/'packaging/release-policy.py');policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)

class ReleasePolicyTests(unittest.TestCase):
    def test_only_matching_stable_tags(self):
        policy.validate('v1.2.3','1.2.3')
        for tag in ['dev','v1.2.3-rc.1','v1.2.4','v1.2.3;echo bad','v1.2']:
            with self.assertRaises(ValueError):policy.validate(tag,'1.2.3')
    def test_dev_only_descendant_cannot_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):return subprocess.run(['git','-C',tmp,*args],capture_output=True,text=True,check=True)
            git('init','-b','main');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
            git('commit','--allow-empty','-m','baseline');git('branch','origin/main');git('switch','-c','dev')
            git('commit','--allow-empty','-m','daily work');git('tag','v0.1.0')
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                policy.require_main_commit('v0.1.0',tmp)
            self.assertEqual(failure.exception.returncode,1)
            git('switch','main');git('merge','--no-ff','dev','-m','milestone');git('branch','-f','origin/main','main')
            policy.require_main_commit('v0.1.0',tmp)

if __name__=='__main__':unittest.main()
