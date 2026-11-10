"""Actual C++ manager -> static Go child -> private CA -> native TLS/readback.

No X11/public listener, system DNS/trust or owner-log reads. The scheduling
boundary is controlled explicitly; natural public CA timing is not claimed.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import ssl
import socket
import subprocess
import tempfile
import threading
import time

from issuer_native import DOMAIN, Upstream, free_port, retire, wait_for
from managed_ca_fixture import PrivateCA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--issuer', required=True, type=Path)
    parser.add_argument('--pebble', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    reports = []
    for slow in (False, True):
        with tempfile.TemporaryDirectory(prefix='traverse-manager-native-') as temporary:
            root = Path(temporary).resolve()
            ca = PrivateCA(root, args.pebble, free_port(), slow=slow)
            upstream = Upstream()
            process, reader, held = None, None, None
            events, failure = queue.Queue(), []
            try:
                upstream.start()
                runtime, data = root/'runtime', root/'data'
                runtime.mkdir(mode=0o700)
                port = ca.bridge.target[1]
                environment = dict(os.environ)
                process = subprocess.Popen([str(args.probe), '--supervisor-pid', str(os.getpid())],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=environment)
                config = {'endpoint': {'schemaVersion': 1, 'domain': DOMAIN, 'port': port,
                                      'certificateSettings': ca.options()}, 'dataHome': str(data),
                          'issuer': str(args.issuer), 'broker': str(runtime/'challenge.sock'),
                          'httpPort': upstream.server_port, 'turnPort': free_port()}
                process.stdin.write(json.dumps(config)+'\n');process.stdin.flush()
                def read_events():
                    try:
                        for line in process.stdout:
                            events.put(json.loads(line))
                    except BaseException as error:
                        failure.append(type(error).__name__)
                reader = threading.Thread(target=read_events);reader.start()
                def event(predicate, description, seconds=30):
                    deadline = time.monotonic()+seconds
                    history=[]
                    while time.monotonic()<deadline:
                        assert not failure and process.poll() is None, 'Native manager exited: '+description
                        try:
                            item = events.get(timeout=min(.1, max(.001, deadline-time.monotonic())))
                        except queue.Empty:
                            continue
                        # Retain only this synthetic producer's typed state;
                        # never export paths, keys, account URLs or owner logs.
                        observed={key:item.get(key) for key in ('managerGeneration','managerPaused',
                            'phase','reason','operationActive','available','proofOnly',
                            'publicationUncertain','frontendRevision','renewAt','checkAt') if key in item}
                        observed['observedWallSeconds']=time.time()
                        if 'fingerprint' in item:
                            observed['frontendMatchesMaterial']=item.get('frontendFingerprint')==item['fingerprint']
                        history.append(observed)
                        if predicate(item):
                            return item
                    raise AssertionError('Native manager timeout: '+description+'; typed states='+json.dumps(history))
                initial = event(lambda value: value.get('proofOnly') and value.get('operationActive'), 'actual bootstrap operation')
                def open_application():
                    raw = socket.create_connection(('127.0.0.1', port), timeout=3)
                    return ssl.create_default_context(cafile=str(ca.issuing_root)).wrap_socket(raw, server_hostname=DOMAIN)
                if slow:
                    started = time.monotonic()
                    while time.monotonic()-started<16:
                        assert process.poll() is None and ca.process.poll() is None
                        time.sleep(.1)
                    pending = initial
                    while not events.empty():
                        pending = events.get_nowait()
                    assert pending.get('operationActive') and pending.get('phase')=='issuing', 'Controlled CA operation was not still pending beyond15s'
                    assert not list(data.glob('traverse/certificates/*/bundle.pem')), 'Slow bootstrap completed before controlled delay'
                    assert ca.bridge.count()>0, 'Slow operation never reached actual private CA validation'
                    try:
                        with open_application():
                            raise AssertionError('Pending workflow admitted application TLS')
                    except (ssl.SSLError, ConnectionResetError):
                        pass
                    before = time.monotonic()
                    process.stdin.write('stop\n');process.stdin.flush()
                    assert process.wait(timeout=3)==0, 'Pending native manager did not stop'
                    reader.join(3);assert not reader.is_alive()
                    reports.append({'slowBootstrapBeyond15s': True, 'applicationDeniedWhilePending': True,
                                    'stopSeconds': time.monotonic()-before, 'realValidationAttempts': ca.bridge.count()})
                    continue
                first = event(lambda value: not value.get('proofOnly', True) and value.get('available') and
                              value.get('frontendFingerprint')==value.get('fingerprint') and not value.get('publicationUncertain'),
                              'actual issued material admitted by native TLS')
                held = open_application()
                def request(stream):
                    stream.sendall(b'GET / HTTP/1.1\r\nHost: '+DOMAIN.encode()+b'\r\nConnection: keep-alive\r\n\r\n')
                    response = http.client.HTTPResponse(stream);response.begin()
                    assert response.status==200 and response.read()==b'Native issuer witness'
                request(held)
                original = hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest()
                states = list(data.glob('traverse/certificates/*'))
                assert len(states)==1
                state = states[0]
                account = (state/'account-key.pem').read_bytes()
                # Restart only the manager around its persisted selection; the
                # native listener and the established application stream stay.
                wait_for(lambda: (state/'schedule.json').exists(), 'persisted schedule', [process])
                saved = json.loads((state/'schedule.json').read_text())
                account_before = json.loads((state/'account.json').read_text())['kid']
                validations = ca.bridge.count()
                process.stdin.write('reload-schedule\n');process.stdin.flush()
                event(lambda value: value.get('managerGeneration')==1 and value.get('fingerprint')==original and not value.get('proofOnly', True), 'cached manager restart')
                request(held)
                assert ca.bridge.count()==validations and (state/'account-key.pem').read_bytes()==account, 'Restart reissued material/account'
                # Explicit scheduler-boundary injection, not a short-lived CA
                # or elapsed natural certificate-renewal demonstration.
                process.stdin.write('pause-manager\n');process.stdin.flush()
                event(lambda value: value.get('managerPaused') is True, 'manager paused for explicit disk scheduling boundary')
                saved = json.loads((state/'schedule.json').read_text())
                saved['schedule']['renewAt'] = int(time.time())-1
                saved['schedule']['checkAt'] = int(time.time())+3600
                replacement = state/'.controlled-schedule.json'
                replacement.write_text(json.dumps(saved));replacement.chmod(0o600);replacement.replace(state/'schedule.json')
                process.stdin.write('reload-schedule\n');process.stdin.flush()
                second = event(lambda value: value.get('managerGeneration')==2 and value.get('available') and value.get('fingerprint')!=original and
                               value.get('frontendFingerprint')==value.get('fingerprint') and not value.get('publicationUncertain'),
                               'due persisted schedule renewed and admitted actual material')
                renewal_observation = {
                    'firstFrontendRevision': first['frontendRevision'],
                    'secondFrontendRevision': second['frontendRevision'],
                    'validationAttemptsBefore': validations,
                    'validationAttemptsAfter': ca.bridge.count(),
                    'firstObservedMaterialMatchesHeldTls': first['fingerprint']==original,
                    'secondMaterialDiffersFromHeldTls': second['fingerprint']!=original,
                    'secondFrontendMatchesMaterial': second['frontendFingerprint']==second['fingerprint'],
                }
                assert second['frontendRevision']>first['frontendRevision'], renewal_observation
                assert renewal_observation['validationAttemptsAfter']>validations, renewal_observation
                request(held)
                assert hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest()==original
                with open_application() as fresh:
                    assert hashlib.sha256(fresh.getpeercert(binary_form=True)).hexdigest()==second['fingerprint']
                assert (state/'account-key.pem').read_bytes()==account and json.loads((state/'account.json').read_text())['kid']==account_before
                reports.append({'bootstrapActualCAAndNativeTLS': True, 'cachedRestartWithoutReissue': True,
                                'controlledPersistedDueScheduleRenewed': True, 'existingTLSSessionContinued': True,
                                'sameAccountKeyAndIdentity': True, 'realValidationAttempts': ca.bridge.count()})
                # Controlled interrupted-order boundary: an intent whose CA
                # URL was never durably recorded is ambiguous. Neither a
                # current TLS certificate nor another restart can clear that
                # uncertainty and silently create a duplicate order.
                process.stdin.write('pause-manager\n');process.stdin.flush()
                event(lambda value: value.get('managerPaused') is True, 'pause before ambiguous-order fixture')
                saved = json.loads((state/'schedule.json').read_text())
                saved['schedule'].update(issuing=True, uncertain=True, admissionPending=False, checkAt=0)
                pending_order = json.loads((state/'pending.json').read_text())
                pending_order['completed'] = False
                pending_order.pop('orderURL', None)
                for filename, record in (('schedule.json', saved), ('pending.json', pending_order)):
                    temporary = state/('.fixture-'+filename)
                    temporary.write_text(json.dumps(record));temporary.chmod(0o600);temporary.replace(state/filename)
                validations = ca.bridge.count()
                process.stdin.write('reload-schedule\n');process.stdin.flush()
                event(lambda value: value.get('managerGeneration')==3 and value.get('reason')=='order_state_uncertain'
                      and value.get('available') and not value.get('operationActive'), 'ambiguous order refused before retry')
                request(held)
                process.stdin.write('reload-schedule\n');process.stdin.flush()
                event(lambda value: value.get('managerGeneration')==4 and value.get('phase')=='failed'
                      and value.get('publicationUncertain') and not value.get('operationActive'),
                      'uncertainty remains after another restart and current-frontend acknowledgement')
                assert ca.bridge.count()==validations and (state/'account-key.pem').read_bytes()==account
                assert json.loads((state/'pending.json').read_text())==pending_order
                reports.append({'controlledAmbiguousOrderNotRetried': True,
                                'uncertaintySurvivesRestartAndCurrentFrontend': True,
                                'validSharingAndExistingTLSPreserved': True})
            finally:
                if held:
                    held.close()
                if process is not None:
                    if process.poll() is None:
                        try:
                            process.stdin.write('stop\n');process.stdin.flush();process.wait(timeout=3)
                        except (OSError, subprocess.TimeoutExpired):
                            retire(process)
                    if process.stdin:
                        process.stdin.close()
                    if reader:
                        reader.join(3);assert not reader.is_alive(), 'Typed fixture observer remained active'
                    if process.stdout:
                        process.stdout.close()
                upstream.close()
                ca.close()
    print(json.dumps({'status': 'passed', 'scope': 'actual manager/static issuer/private CA/native TLS; controlled schedule boundary',
                      'cases': reports, 'publicCA': False, 'ownerLogsReadOrExported': False}), flush=True)


if __name__=='__main__':
    main()
