"""Disposable ordinary Chrome/CDP fixture; no TLS or sandbox bypass flags."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import websocket
from issuer_native import wait_for
from installed_standalone import alive, descendants

CLIENT_UID = CLIENT_GID = 65533
# The module attaches this handler after parsing the form. DOM presence alone
# permits native form submission before the client code can prevent it.
PAIRING_READY = "window.isSecureContext && typeof document.getElementById('pairForm')?.onsubmit === 'function'"


class CDP:
    def __init__(self, url):
        self.connection = websocket.create_connection(url, timeout=10, suppress_origin=True,
            http_proxy_host=None, http_proxy_port=None, http_no_proxy=['127.0.0.1','localhost'])
        self.serial = 0
        self.responses = []

    def call(self, method, params=None, session=None):
        self.serial += 1
        message = {'id': self.serial, 'method': method, 'params': params or {}}
        if session: message['sessionId'] = session
        self.connection.send(json.dumps(message))
        while True:
            reply = json.loads(self.connection.recv())
            if reply.get('method') == 'Network.responseReceived':
                self.responses.append(reply['params']['response'])
            if reply.get('id') != self.serial: continue
            if 'error' in reply: raise AssertionError('CDP command failed: '+method)
            return reply.get('result', {})

    def close(self):
        self.connection.close()


class Browser:
    def __init__(self, home, profile, environment):
        self.home, self.profile = Path(home), Path(profile)
        self.profile.mkdir(mode=0o700)
        os.chown(self.profile, CLIENT_UID, CLIENT_GID)
        self.error_path = self.home/(self.profile.name+'-stderr.txt')
        self.errors = self.error_path.open('w')
        self.process = subprocess.Popen(['xvfb-run', '-a', '-s', '-screen 0 1280x900x24',
            '/usr/bin/google-chrome-stable', '--user-data-dir='+str(self.profile),
            '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check',
            '--enable-automation', 'about:blank'], env=environment,
            user=CLIENT_UID, group=CLIENT_GID, extra_groups=[],
            stdout=subprocess.DEVNULL, stderr=self.errors, start_new_session=True)
        self.cdp = None
        try:
            def endpoint():
                assert self.process.poll() is None, 'Ordinary Chrome exited before its private debugger was ready'
                path=self.profile/'DevToolsActivePort'
                if not path.exists(): return None
                lines=path.read_text().splitlines()
                if len(lines)!=2: return None
                return 'ws://127.0.0.1:'+lines[0]+lines[1]
            self.cdp=CDP(wait_for(endpoint, 'Ordinary Chrome debugger', [self.process], seconds=30))
            self.version=self.cdp.call('Browser.getVersion')
            arguments=self.cdp.call('Browser.getBrowserCommandLine')['arguments']
            forbidden=('--ignore-certificate-errors', '--allow-insecure-localhost', '--no-sandbox',
                       '--disable-setuid-sandbox', '--disable-web-security')
            assert not any(any(a==flag or a.startswith(flag+'=') for flag in forbidden) for a in arguments)
            target=self.cdp.call('Target.createTarget', {'url':'about:blank'})['targetId']
            self.session=self.cdp.call('Target.attachToTarget', {'targetId':target, 'flatten':True})['sessionId']
            self.send('Page.enable');self.send('Runtime.enable');self.send('Network.enable')
        except BaseException as error:
            self.errors.flush()
            diagnostic=self.error_path.read_text()
            self.close()
            # Constructor starts about:blank in a new profile; no pairing or
            # controller material has entered this browser at this boundary.
            raise AssertionError('Ordinary Chrome startup failed: '+diagnostic) from error

    def send(self, method, params=None):
        return self.cdp.call(method, params, self.session)

    def evaluate(self, expression):
        result=self.send('Runtime.evaluate', {'expression':expression, 'awaitPromise':True,
            'returnByValue':True})
        assert 'exceptionDetails' not in result, 'Private Chrome evaluation failed'
        return result['result'].get('value')

    def navigate(self, url):
        return self.send('Page.navigate', {'url':url})

    def wait(self, expression, description, seconds=30):
        return wait_for(lambda:self.evaluate(expression), description, [self.process], seconds=seconds)

    def key(self, kind, key, code, virtual):
        return self.send('Input.dispatchKeyEvent', {'type':kind, 'key':key, 'code':code,
            'windowsVirtualKeyCode':virtual, 'nativeVirtualKeyCode':virtual})

    def close(self):
        owned=descendants(self.process.pid)
        channel=self.cdp;self.cdp=None
        try:
            if channel:
                try:channel.call('Browser.close')
                except (OSError, websocket.WebSocketException):pass
                finally:channel.close()
        finally:
            if self.process.poll() is None:
                try:self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGTERM)
                    try:self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.process.pid, signal.SIGKILL);self.process.wait(timeout=5)
            self.errors.close()
            wait_for(lambda:not any(alive(pid) for pid in owned), 'Owned Chrome children stopped', seconds=10)
