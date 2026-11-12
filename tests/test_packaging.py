import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import json
import hashlib
import os
import shutil
import sys

ROOT=Path(__file__).resolve().parent.parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

package=load('package','packaging/package.py')
fetch=load('fetch','packaging/fetch-sources.py')

class PackagingTests(unittest.TestCase):
    def test_private_source_snapshot_hashes_actual_code_and_marks_git_basis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'host').mkdir();code=root/'host/main.cpp';code.write_text('current app source')
            first=package.source_snapshot(root,'a'*40)
            self.assertEqual(first['kind'],'private-source-snapshot');self.assertEqual(first['gitBasis'],'a'*40)
            self.assertEqual(first['files'],{'host/main.cpp':hashlib.sha256(code.read_bytes()).hexdigest()})
            code.write_text('changed current app source');second=package.source_snapshot(root,'a'*40)
            self.assertNotEqual(first['sha256'],second['sha256'])
    @unittest.skipUnless(sys.platform.startswith('linux'),'Linux host entry and ELF tools')
    def test_host_entry_relocation_quotes_and_clean_media_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix=Path(temporary)/'runtime with spaces';(prefix/'bin').mkdir(parents=True)
            executable=prefix/'libexec/traverse/traverse-host';executable.parent.mkdir(parents=True)
            executable.write_text('#!/bin/sh\nprintf "%s\\0" "$@" "${LD_LIBRARY_PATH-unset}" "${TRAVERSE_RUNTIME_PREFIX-unset}" "${GST_PLUGIN_SYSTEM_PATH_1_0-unset}" "$DISPLAY" "$QT_SCALE_FACTOR"\n');executable.chmod(0o755)
            entry=prefix/'bin/traverse-host';shutil.copyfile(ROOT/'packaging/host-entry.sh',entry);entry.chmod(0o755)
            env=dict(os.environ,LD_LIBRARY_PATH=str(prefix/'lib'),TRAVERSE_RUNTIME_PREFIX=str(prefix),GST_PLUGIN_SYSTEM_PATH_1_0=str(prefix/'lib/gstreamer-1.0'),DISPLAY=':98',QT_SCALE_FACTOR='2')
            result=subprocess.check_output([str(entry),'--config','a file with spaces.json'],env=env)
            self.assertEqual(result.split(b'\0')[:-1],[b'--prefix',str(prefix.resolve()).encode(),b'--config',b'a file with spaces.json',b'unset',b'unset',b'unset',b':98',b'2'])
            for option in ('--owner-fd','--owner-fd=9'):
                rejected=subprocess.run([str(entry),option],env=env,capture_output=True)
                self.assertNotEqual(rejected.returncode,0);self.assertEqual(rejected.stdout,b'')
    @unittest.skipUnless(sys.platform.startswith('linux'),'Real Linux ELF classification')
    def test_only_exact_regular_host_elf_is_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix=Path(temporary);ui=prefix/'libexec/traverse/traverse-host';ui.parent.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError,'Missing or unexpected'):package.media_elfs(prefix,ui)
            ui.symlink_to('/bin/true')
            with self.assertRaisesRegex(ValueError,'Missing or unexpected'):package.media_elfs(prefix,ui)
            ui.unlink();shutil.copyfile('/bin/true',ui)
            native=ui.with_name('native-helper');shutil.copyfile('/bin/true',native)
            self.assertEqual(package.media_elfs(prefix,ui),[native])
            with self.assertRaisesRegex(ValueError,'Missing or unexpected'):package.media_elfs(prefix,native)
            actual=os.environ.get('TRAVERSE_TEST_SYSTEM_UI_ELF')
            if actual:
                shutil.copyfile(actual,native)
                with self.assertRaisesRegex(ValueError,'Unexpected Qt consumer'):package.media_elfs(prefix,ui)
    def test_cached_issuer_source_must_match_current_project(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);project=root/'issuer';project.mkdir()
            source=project/'main.go';source.write_text('package main\n// current helper\n')
            archive=root/'issuer.tar.gz'
            with tarfile.open(archive,'w:gz') as output:output.add(project,arcname='certificate-issuer')
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            package.verify_issuer_source_archive(archive,digest,project)
            source.write_text('package main\n// added renewal-info\n')
            with self.assertRaisesRegex(ValueError,'current project source'):
                package.verify_issuer_source_archive(archive,digest,project)
            with self.assertRaisesRegex(ValueError,'build identity'):
                package.verify_issuer_source_archive(archive,'0'*64,project)
    def test_pipewire_provider_declares_dynamic_client_assets(self):
        manifest=json.loads((ROOT/'packaging/runtime-manifest.json').read_text())
        sources={source['name']:source for source in manifest['sources']}
        self.assertIn('pipewire',sources,'Private capture provider must be pinned with the runtime sources')
        provider=manifest['pipewireCaptureProvider']
        self.assertEqual(provider['version'],sources['pipewire']['version'])
        self.assertIn('share/pipewire/client.conf',provider['assets'])
        self.assertIn('lib/pipewire-0.3/libpipewire-module-protocol-native.so',provider['assets'])
        self.assertIn('lib/spa-0.2/support/libspa-support.so',provider['assets'])
        self.assertIn('lib/spa-0.2/support/libspa-dbus.so',provider['assets'])
    def test_pipewire_assets_are_copied_to_the_relocated_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp)/'build-prefix';runtime.mkdir()
            prefix=Path(tmp)/'relocated';prefix.mkdir()
            name='lib/pipewire-0.3/libpipewire-module-protocol-native.so'
            source=runtime/name;source.parent.mkdir(parents=True);source.write_bytes(b'owned provider')
            assets=package.collect_pipewire_assets(runtime,prefix,{'assets':[name]})
            self.assertEqual(assets,[prefix/name])
            self.assertEqual((prefix/name).read_bytes(),b'owned provider')
            self.assertEqual((prefix/name).stat().st_mode & 0o777,0o644)
    def test_pipewire_asset_manifest_rejects_missing_and_escaping_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp)/'runtime';runtime.mkdir()
            prefix=Path(tmp)/'stage';prefix.mkdir()
            outside=Path(tmp)/'outside';outside.write_bytes(b'outside')
            (runtime/'link').symlink_to(outside)
            for name in ('missing','../outside','/absolute','link'):
                with self.subTest(name=name),self.assertRaises(ValueError):
                    package.collect_pipewire_assets(runtime,prefix,{'assets':[name]})
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
    def test_explicit_build_exclusions_skip_only_the_named_subtrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source.tar'
            with tarfile.open(path,'w') as tar:
                tar.addfile(tarfile.TarInfo('source/src/main.c'))
                link=tarfile.TarInfo('source/examples/key.pem');link.type=tarfile.SYMTYPE;link.linkname='../fixture/key.pem';tar.addfile(link)
            target=Path(tmp)/'out'
            fetch.safe_extract(path,target,['examples'])
            self.assertTrue((target/'source/src/main.c').is_file())
            self.assertFalse((target/'source/examples').exists())
            with self.assertRaises(ValueError):fetch.safe_extract(path,Path(tmp)/'strict')
    def test_build_exclusions_do_not_hide_traversal_or_other_links(self):
        for name,kind in [('source/examples/../../escape',tarfile.REGTYPE),('source/src/link',tarfile.SYMTYPE),('/source/examples/escape',tarfile.REGTYPE)]:
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'source.tar'
                with tarfile.open(path,'w') as tar:
                    member=tarfile.TarInfo(name);member.type=kind;member.linkname='/etc/passwd';tar.addfile(member)
                with self.assertRaises(ValueError):fetch.safe_extract(path,Path(tmp)/'out',['examples'])
        with tempfile.TemporaryDirectory() as tmp:
            for invalid in ['/absolute','../outside','']:
                with self.assertRaises(ValueError):fetch.safe_extract(Path(tmp)/'absent.tar',Path(tmp)/'out',[invalid])

if __name__=='__main__':unittest.main()
