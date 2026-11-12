"""Installed private worker through the real native owner, no desktop grant UI.

The probe and private D-Bus fixture are external test tools. No test server or
Python controller is installed in the product. A compositor trial is separate.
"""
import hashlib
import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

root=Path(__file__).resolve().parent.parent
prefix=Path(sys.argv[1] if len(sys.argv)>1 else '/opt/traverse').resolve()
build=Path(os.environ.get('TRAVERSE_NATIVE_TEST_BUILD',str(root/'.work/build-native'))).resolve()
worker=prefix/'libexec/traverse/traverse-wayland-guardian'
manifest_bytes=(prefix/'share/traverse/runtime-manifest.json').read_bytes()
manifest=json.loads(manifest_bytes)
expected=Path(os.environ.get('TRAVERSE_EXPECTED_RUNTIME_MANIFEST',
    str(root/'.work/stage/opt/traverse/share/traverse/runtime-manifest.json')))
assert manifest_bytes==expected.read_bytes(),'Installed artifact differs from the intended build manifest'
for name,digest in manifest['payloadSha256'].items():
    assert hashlib.sha256((prefix/name).read_bytes()).hexdigest()==digest,name
assert 'traverse-wayland-guardian' in manifest['runtime_executables']
assert 'lib/libei.so.1' in manifest['dynamicProviderAssets']
assert not list(prefix.rglob('libeis.so*')),'Test-only libeis in product'

product_environment=dict(os.environ,TRAVERSE_RUNTIME_PREFIX=str(prefix),LD_LIBRARY_PATH=str(prefix/'lib'),
    GST_PLUGIN_PATH_1_0='',GST_PLUGIN_SYSTEM_PATH_1_0=str(prefix/'lib/gstreamer-1.0'),
    GST_PLUGIN_SCANNER=str(prefix/'libexec/gstreamer-1.0/gst-plugin-scanner'),
    PIPEWIRE_MODULE_DIR=str(prefix/'lib/pipewire-0.3'),SPA_PLUGIN_DIR=str(prefix/'lib/spa-0.2'),
    PIPEWIRE_CONFIG_DIR=str(prefix/'share/pipewire'),PIPEWIRE_CONFIG_PREFIX='',PIPEWIRE_CONFIG_NAME='client.conf')
# Import the shared real-bus fixture after resolving paths: it drops test root.
sys.argv=[sys.argv[0],str(build/'portal-session-probe'),str(build/'wayland-controller-probe'),str(worker)]
import wayland_controller_test as controller

class Installed(controller.NativeController):
    @contextlib.contextmanager
    def owner(self,mode='valid',worker=controller.WORKER):
        with self.mutex:type(self).mode=mode
        peer=controller.Peer(worker,dict(product_environment,DBUS_SESSION_BUS_ADDRESS=self.address))
        try:yield peer
        finally:peer.close()
    def test_installed_loading_origins_and_reap(self):
        with self.owner() as peer:
            state=self.ready(peer)
            mappings=Path('/proc/'+str(state['pid'])+'/maps').read_text().splitlines()
            paths={line.split()[-1] for line in mappings if len(line.split())>=6 and line.split()[-1].startswith('/')}
            self.assertIn(str(worker),paths)
            self.assertIn(str(prefix/'lib/libei.so.1'),paths)
            self.assertFalse(any('libeis.so' in path for path in paths))
            # Every mapped ELF library except glibc/loader comes from the
            # installed prefix, even if a build tree is visible to the test.
            glibc=('libc.so.','libm.so.','libpthread.so.','libdl.so.','librt.so.',
                'libresolv.so.','libutil.so.','ld-linux','ld-2.')
            for path in paths:
                name=Path(path).name
                if '.so' in name and not name.startswith(glibc):
                    self.assertTrue(Path(path).is_relative_to(prefix),path)
            self.assertTrue(peer.stop()['ok'])
            self.assertFalse(Path('/proc/'+str(state['pid'])).exists())

names=['test_installed_loading_origins_and_reap','test_constructor_thread_exit_and_exact_reap',
    'test_completion_waits_for_actual_bus_reply_and_stop_releases',
    'test_stop_cancels_pending_native_input_without_ack',
    'test_stop_during_permission_and_capability_wait','test_stop_cancels_pending_capture_connection',
    'test_native_failure_and_denial_are_preserved','test_unexpected_child_exit_fences_cached_authority']
with tempfile.TemporaryDirectory(prefix='traverse-installed-wayland-') as cache:
    product_environment['GST_REGISTRY']=cache+'/registry.bin'
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Installed(name) for name in names))
    if not result.wasSuccessful():raise SystemExit(1)
print(json.dumps(dict(scope='Installed private C++ owner/worker protocol, not compositor or Chrome support',
    prefix=str(prefix),workerSha256=manifest['payloadSha256']['libexec/traverse/traverse-wayland-guardian'],
    manifestSha256=hashlib.sha256(manifest_bytes).hexdigest(),
    checks=result.testsRun)),flush=True)
