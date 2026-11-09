import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import subprocess

ROOT=Path(__file__).resolve().parent.parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

package=load('package','packaging/package.py')
fetch=load('fetch','packaging/fetch-sources.py')

class PackagingTests(unittest.TestCase):
    def test_project_version(self):
        self.assertEqual(package.version_from_cmake('project(traverse VERSION 1.2.3 LANGUAGES CXX)'), '1.2.3')
        for version in ['1.2','1.2.3; touch /tmp/pwn','../1.2.3','v1.2.3']:
            with self.assertRaises(ValueError):package.validate_version(version)
    def test_abi_gate_uses_numeric_versions(self):
        package.validate_abi('GLIBC_2.9 GLIBC_2.35', '2.35')
        with self.assertRaises(ValueError):package.validate_abi('GLIBC_2.36','2.35')
    def test_distribution_owner_resolves_library_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            actual=Path(tmp).resolve()/'usr-lib/libexample.so.1.0';actual.parent.mkdir();actual.write_bytes(b'library')
            alias=Path(tmp)/'libexample.so.1';alias.symlink_to(actual)
            def query(args,**kwargs):
                if Path(args[-1])==actual:return 'libexample:amd64: '+str(actual)+'\n'
                raise subprocess.CalledProcessError(1,args)
            with patch.object(package,'run',side_effect=query):
                self.assertEqual(package.distribution_owners(alias),{'libexample:amd64'})
    def test_unknown_distribution_owner_fails_closed(self):
        with tempfile.NamedTemporaryFile() as source:
            with patch.object(package,'run',side_effect=subprocess.CalledProcessError(1,['dpkg-query'])):
                with self.assertRaises(ValueError):package.distribution_owners(source.name)
    def test_archive_rejects_traversal_and_links(self):
        for name,kind in [('../escape',tarfile.REGTYPE),('/escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('hard',tarfile.LNKTYPE)]:
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'source.tar'
                with tarfile.open(path,'w') as tar:
                    item=tarfile.TarInfo(name);item.type=kind;item.linkname='/etc/passwd';tar.addfile(item)
                with self.assertRaises(ValueError):fetch.safe_extract(path,Path(tmp)/'out')
    def test_archive_allows_regular_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source.tar'
            with tarfile.open(path,'w') as tar:
                item=tarfile.TarInfo('source/README');item.size=0;tar.addfile(item)
            fetch.safe_extract(path,Path(tmp)/'out')
            self.assertTrue((Path(tmp)/'out/source/README').is_file())

if __name__=='__main__':unittest.main()
