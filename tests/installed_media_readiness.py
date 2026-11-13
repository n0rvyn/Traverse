"""Installed fixed helper roles, shared TCP/UDP443 and native media ownership.

Root observes only the isolated fixture. Every app process runs as UID65534;
this does not substitute for final DEB/RPM/ARM or outside-network acceptance.
"""
import os
from pathlib import Path
import socket
import sys
import ssl
import unittest
import json
import types

PREFIX=Path(os.environ.get('TRAVERSE_TEST_PREFIX','/opt/traverse')).resolve()
helpers=PREFIX/'libexec/traverse'
sys.argv=[sys.argv[0],str(helpers/'traverse-readiness-media'),str(helpers/'traverse-service'),
    str(helpers/'traverse-adapter'),os.environ['TRAVERSE_TEST_OWNER_PROBE'],str(PREFIX/'share/traverse/web')]
import readiness_media_service_test as media
from installed_managed_certificates import require_disposable_environment
from bind_helper_test import verify_threads,BIND
media.fixture.PREFIX=PREFIX


class InstalledMediaTests(media.MediaServiceTests):
    def spawn(self,arguments):
        # The inherited raw-TURN lifecycle test uses this already listening
        # shared443 frontend, rather than making a second public listener.
        if arguments[0]==str(helpers/'traverse-tls-frontend') and hasattr(self,'frontend'):
            return self.frontend
        return super().spawn(arguments)

    def start_service(self):
        self.port=int(os.environ.get('TRAVERSE_TEST_APP_PORT','443'))
        self.media_port=self.port
        self.origin='https://'+media.fixture.DOMAIN+('' if self.port==443 else ':'+str(self.port))
        http_port=media.fixture.free_port()
        service_entry=[str(helpers/'traverse-bind-helper'),'service'] if self.port<1024 else [str(helpers/'traverse-service')]
        frontend_entry=[str(helpers/'traverse-bind-helper'),'frontend'] if self.port<1024 else [str(helpers/'traverse-tls-frontend')]
        self.service=self.spawn(service_entry+['--internal-http',
            '--host','127.0.0.1','--port',str(http_port),'--origin',self.origin,'--base-path',self.base,
            '--web',str(PREFIX/'share/traverse/web'),'--socket',str(self.adapter_socket),
            '--owner-socket',str(self.owner_socket),'--stun','','--udp-port',str(self.media_port),
            '--udp-only','--media-readiness','--media-probe-socket',str(self.private/'mp'),
            '--supervisor-pid',str(os.getpid())])
        def owner_ready():
            if self.service.poll() is not None:
                log=self.logs[self.processes.index(self.service)];log.seek(0)
                raise AssertionError(('Installed service exited',self.service.returncode,log.read()))
            return self.owner_socket.exists()
        media.fixture.wait(owner_ready,
            'Installed service owner socket',timeout=15)
        self.frontend=self.spawn(frontend_entry+['--host','127.0.0.1',
            '--port',str(self.port),'--http-port',str(http_port),'--turn-port',str(http_port),
            '--cert',str(self.certificate),'--key',str(self.key),'--expected-domain',media.fixture.DOMAIN,
            '--trust-file',str(self.certificate),'--trust-directory','','--probe-socket',str(self.private/'mp'),
            '--probe-owner-pid',str(self.service.pid),'--supervisor-pid',str(os.getpid())])
        def ready():
            self.assertIsNone(self.service.poll());self.assertIsNone(self.frontend.poll())
            try:return self.public('',method='GET')[0]==200
            except (OSError,ssl.SSLError,media.fixture.http.client.HTTPException):return False
        media.fixture.wait(ready,'Installed shared-port trusted HTTPS',timeout=15)
        self.assertEqual(Path(f'/proc/{self.service.pid}/exe').resolve(),helpers/'traverse-service')
        if self.port<1024:self.assertGreater(verify_threads(self.service.pid,BIND),0)
        else:
            # Plain high-port service is the existing unprivileged launch path,
            # rather than a new use of the capability-bearing helper.
            tasks=list(Path(f'/proc/{self.service.pid}/task').iterdir());self.assertTrue(tasks)
            for task in tasks:
                fields=dict(line.split(':',1) for line in (task/'status').read_text().splitlines() if ':' in line)
                for key in ('Uid','Gid'):self.assertEqual(set(map(int,fields[key].split())),{65534})
                for key in ('CapEff','CapPrm','CapInh','CapAmb'):self.assertEqual(int(fields[key],16),0)
        self.assertGreater(verify_threads(self.frontend.pid,0),0)

    def source_pid(self):
        pid=super().source_pid()
        # This is the existing network-only binding capability, inherited from
        # the unchanged service helper role to bind the fixed low UDP port.
        self.assertGreater(verify_threads(pid,BIND if self.port<1024 else 0),0)
        for process in (self.service.pid,pid):
            mappings=Path(f'/proc/{process}/maps').read_text().splitlines()
            libraries=[line.split()[-1] for line in mappings if '/' in line and any(
                name in line.split()[-1] for name in ('libgstreamer-','libnice.so','libssl.so'))]
            self.assertTrue(libraries,'Installed library mapping positive control missing')
            self.assertTrue(all(Path(name).is_relative_to(PREFIX) for name in libraries),libraries)
        def socket_inodes(process):
            result=set()
            for fd in Path(f'/proc/{process}/fd').iterdir():
                try:link=os.readlink(fd)
                except FileNotFoundError:continue
                if link.startswith('socket:['):result.add(link)
            return result
        parent_sockets=socket_inodes(self.service.pid)|socket_inodes(self.frontend.pid)
        self.assertTrue(parent_sockets,'Installed parent listener positive control missing')
        self.assertFalse(parent_sockets & socket_inodes(pid),'Source inherited parent listener/owner descriptors')
        for task in Path(f'/proc/{self.service.pid}/task').iterdir():
            for child in (task/'children').read_text().split():
                if int(child)!=pid:self.assertGreater(verify_threads(int(child),0),0)
        fields=Path(f'/proc/{pid}/environ').read_bytes()
        for key in (b'DISPLAY=',b'WAYLAND_DISPLAY=',b'XAUTHORITY=',b'XDG_RUNTIME_DIR=',b'DBUS_SESSION_BUS_ADDRESS='):
            self.assertFalse(any(item.startswith(key) for item in fields.split(b'\0')))
        return pid


class InstalledLauncherMediaTests(InstalledMediaTests):
    def start_service(self):
        # Start the actual normal entry, which owns its own adapter and service.
        self.adapter.terminate();self.adapter.wait(timeout=5)
        self.port=int(os.environ.get('TRAVERSE_TEST_APP_PORT','443'));self.media_port=self.port
        self.origin='https://'+media.fixture.DOMAIN+('' if self.port==443 else ':'+str(self.port))
        runtime=self.private/'r';runtime.mkdir(mode=0o700);os.chown(runtime,self.uid,self.uid)
        self.adapter_socket=runtime/'traverse/adapter.sock'
        self.native_env.update(XDG_RUNTIME_DIR=str(runtime),SSL_CERT_FILE=str(self.certificate),SSL_CERT_DIR='')
        config=self.private/'config.json'
        config.write_text(json.dumps(dict(schemaVersion=1,domain=media.fixture.DOMAIN,port=self.port,basePath=self.base,
            certificate=str(self.certificate),privateKey=str(self.key),listenAddress='127.0.0.1')))
        config.chmod(0o600);os.chown(config,self.uid,self.uid)
        self.launch=self.spawn([str(PREFIX/'bin/traverse'),'--config',str(config)])
        from installed_standalone import children,alive
        def ready():
            if self.launch.poll() is not None:
                log=self.logs[self.processes.index(self.launch)];log.seek(0)
                raise AssertionError(('Normal launcher exited',self.launch.returncode,log.read()))
            roles={}
            for pid in children(self.launch.pid):
                try:
                    if alive(pid):roles[Path(f'/proc/{pid}/exe').resolve().name]=pid
                except (FileNotFoundError,ProcessLookupError):
                    # A short-lived runtime check can exit between the kernel
                    # child snapshot and reading its executable identity.
                    continue
            if not {'traverse-service','traverse-tls-frontend','traverse-adapter','turnserver'}<=roles.keys():return False
            self.service=types.SimpleNamespace(pid=roles['traverse-service'])
            frontend_pid=roles['traverse-tls-frontend']
            self.frontend=types.SimpleNamespace(pid=frontend_pid,poll=lambda:None if alive(frontend_pid) else -1)
            arguments=Path(f'/proc/{self.service.pid}/cmdline').read_bytes().decode().split('\0')
            self.assertIn('--media-readiness',arguments)
            if '--owner-socket' not in arguments:return False
            self.owner_socket=Path(arguments[arguments.index('--owner-socket')+1])
            if not self.owner_socket.exists():return False
            try:return self.public('',method='GET')[0]==200
            except (OSError,ssl.SSLError,media.fixture.http.client.HTTPException):return False
        media.fixture.wait(ready,'Normal installed launcher with media broker',timeout=20)

    def close(self):
        from installed_standalone import descendants,alive
        owned=descendants(self.launch.pid) if hasattr(self,'launch') else []
        super().close()
        self.assertFalse(any(alive(pid) for pid in owned),'Normal launcher left an owned process running')


if __name__=='__main__':
    require_disposable_environment()
    unittest.main(defaultTest=[
        'InstalledMediaTests.test_purpose_authority_invalid_pair_and_genuine_pair_preemption',
        'InstalledMediaTests.test_service_relay_owned_grant_and_pair_reaps_every_child',
        'InstalledMediaTests.test_service_death_revokes_live_relay_and_source',
        'InstalledMediaTests.test_genuine_pair_during_relay_setup',
        'InstalledLauncherMediaTests.test_purpose_authority_invalid_pair_and_genuine_pair_preemption',
        'InstalledLauncherMediaTests.test_service_relay_owned_grant_and_pair_reaps_every_child'])
