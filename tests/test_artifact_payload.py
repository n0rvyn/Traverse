import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('artifact_payload', Path(__file__).with_name('artifact_payload.py'))
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)


class ArtifactPayloadTests(unittest.TestCase):
    def test_ui_hash_and_system_qt_boundary_are_independent_of_inventory(self):
        files={'libexec/traverse/traverse-issuer':b'issuer','libexec/traverse/traverse-host':b'checked UI bytes','bin/traverse-host':b'clean entry'}
        manifest={'sourceCommit':'a'*40,'certificateIssuer':{'build':{'binarySha256':hashlib.sha256(files['libexec/traverse/traverse-issuer']).hexdigest()}},
                  'hostUi':{'executable':'libexec/traverse/traverse-host','entry':'bin/traverse-host','build':{'binarySha256':hashlib.sha256(files['libexec/traverse/traverse-host']).hexdigest()}}}
        with tempfile.TemporaryDirectory() as temporary:
            archive=Path(temporary)/'portable.tar.gz'
            def write():
                manifest['payloadSha256']={name:hashlib.sha256(data).hexdigest() for name,data in files.items()}
                with tarfile.open(archive,'w:gz') as output:
                    for name,data in dict(files,**{payload.MANIFEST:json.dumps(manifest).encode()}).items():
                        entry=tarfile.TarInfo('traverse/'+name);entry.size=len(data);output.addfile(entry,io.BytesIO(data))
            write();self.assertEqual(payload.verify(archive)['verifiedPayloadFiles'],3)
            files['libexec/traverse/traverse-host']+=b'unchecked rewrite';write()
            with self.assertRaisesRegex(ValueError,'differs from checked system UI'):payload.verify(archive)
            manifest['hostUi']['build']['binarySha256']=hashlib.sha256(files['libexec/traverse/traverse-host']).hexdigest()
            files['lib/libQt6Core.so.6']=b'Qt must remain a system dependency';write()
            with self.assertRaisesRegex(ValueError,'Distribution Qt'):payload.verify(archive)
            files.pop('lib/libQt6Core.so.6');files.pop('bin/traverse-host');write()
            with self.assertRaisesRegex(ValueError,'differs from checked system UI'):payload.verify(archive)
    def test_actual_archive_accepts_inventory_and_rejects_changed_missing_or_extra_bytes(self):
        original = {'libexec/traverse/traverse-issuer': b'known issuer bytes', 'lib/provider.chk': b'paired integrity bytes'}
        manifest = {'sourceCommit': 'a'*40, 'payloadSha256': {name: hashlib.sha256(data).hexdigest() for name, data in original.items()},
                    'certificateIssuer': {'build': {'binarySha256': hashlib.sha256(original['libexec/traverse/traverse-issuer']).hexdigest()}}}
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary)/'portable.tar.gz'
            def write(files):
                with tarfile.open(archive, 'w:gz') as output:
                    for name, data in dict(files, **{payload.MANIFEST: json.dumps(manifest).encode()}).items():
                        entry = tarfile.TarInfo('traverse/'+name); entry.size = len(data)
                        output.addfile(entry, io.BytesIO(data))
            write(original)
            self.assertEqual(payload.verify(archive)['verifiedPayloadFiles'], 2)
            changed = dict(original); changed['libexec/traverse/traverse-issuer'] += b'altered after assembly'
            missing = dict(original); missing.pop('lib/provider.chk')
            extra = dict(original); extra['lib/uninventoried.so'] = b'extra'
            for files in (changed, missing, extra):
                write(files)
                with self.assertRaisesRegex(ValueError, 'differ from payload inventory'):
                    payload.verify(archive)


if __name__ == '__main__':
    unittest.main()
