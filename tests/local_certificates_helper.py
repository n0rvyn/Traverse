"""Actual static helper in an owned Linux network/PID/mount namespace.

Called by a private build runner, never against a live certificate directory.
Only sanitized results/hashes are written to the supplied evidence path.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time


def retire(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=5)


def wait_stdin_select(process_id):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        tasks = Path(f'/proc/{process_id}/task')
        assert tasks.exists(), 'Owned helper exited before reaching stdin wait'
        for task in tasks.iterdir():
            try:
                fields = (task/'syscall').read_text().split()
                if len(fields)>1 and fields[0] in ('23','72','270') and fields[1]=='0x1':
                    return
            except FileNotFoundError:
                pass
        time.sleep(.01)
    raise AssertionError('Owned helper never reached guarded stdin select')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--issuer',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    assert sys.platform=='linux' and os.getpid()>1
    addresses=json.loads(subprocess.check_output(['ip','-json','address','show'],text=True))
    routes=json.loads(subprocess.check_output(['ip','-json','route','show','table','all'],text=True))
    assert [a['ifname'] for a in addresses]==['lo'] and not any(r.get('dst')=='default' for r in routes)
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=True)
    report={'status':'failed','scope':'Actual static helper, isolated Linux network/PID/mount namespace; no native launcher/browser trust claim',
            'helperSha256':hashlib.sha256(args.issuer.read_bytes()).hexdigest(),'loopbackOnly':True,'defaultRoutes':0}
    with tempfile.TemporaryDirectory(prefix='traverse-local-helper-',dir='/dev/shm') as temporary:
        root=Path(temporary)
        observed=[]
        def trace(command,source):
            destination=root/(str(len(observed))+'-network.txt')
            run=subprocess.run(['strace','-f','-qq','-e','trace=network','-e','signal=none','-o',str(destination),*command],
                               input=source,capture_output=True,text=True,timeout=20)
            assert run.returncode==0, 'Owned syscall observation command failed'
            records=[line for line in destination.read_text().splitlines() if line.strip() and
                     'exited with' not in line and 'killed by' not in line]
            observed.append(dict(traceSha256=hashlib.sha256(destination.read_bytes()).hexdigest(),networkRecords=len(records)))
            return run,records
        positive,_=trace([sys.executable,'-c',"import socket\ns=socket.socket()\ntry:s.connect(('127.0.0.1',9))\nexcept OSError:pass\ns.close()"],None)
        assert positive.returncode==0 and observed[0]['networkRecords']>0, 'Observer has no positive network control'
        request=dict(version=1,operation='local-ensure',domain='offline.test',stateDirectory=str(root/'authority'))
        command=[str(args.issuer)]
        generated,records=trace(command,json.dumps(request))
        assert not records, 'Local generation attempted network syscalls'
        first=json.loads(generated.stdout)
        assert first['status']=='local-issued' and first['local']['authority']=='current' and first['publication']['durable']
        repeated,records=trace(command,json.dumps(request))
        assert not records, 'Repeated local generation attempted network syscalls'
        second=json.loads(repeated.stdout)
        assert second['status']=='local-ready' and second['local']['root']==first['local']['root'] and second['local']['leaf']==first['local']['leaf']
        request['operation']='local-info'
        inspected,records=trace(command,json.dumps(request))
        assert not records and json.loads(inspected.stdout)['status']=='local-info'
        report.update(networkObserver=observed,localGenerationAndReuseNoNetwork=True,
                      rootFingerprint=first['local']['root']['fingerprint'],leafFingerprint=first['local']['leaf']['fingerprint'])
        for mode in ('eof','sigterm'):
            private=root/(mode+'-state')
            process=subprocess.Popen([str(args.issuer),'--supervisor-pid',str(os.getpid())],stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                partial=dict(version=1,operation='local-ensure',domain='offline.test',stateDirectory=str(private))
                process.stdin.write(json.dumps(partial)[:-1]);process.stdin.flush()
                wait_stdin_select(process.pid)
                if mode=='eof':
                    process.stdin.close();process.stdin=None
                    stdout,stderr=process.communicate(timeout=5)
                else:
                    # Keep stdin open until exit, so EOF cannot explain a
                    # successful SIGTERM cancellation observation.
                    process.terminate();process.wait(timeout=5)
                    stdout,stderr=process.stdout.read(),process.stderr.read()
                result=json.loads(stdout)
                assert process.returncode==1 and result['status']=='failed'
                assert result['code']==('invalid_request' if mode=='eof' else 'cancelled')
                assert not private.exists() and 'PRIVATE KEY' not in stdout+stderr
                report[mode]=dict(status='passed',exitCode=process.returncode,helperReaped=True)
            finally:
                retire(process)
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream and not stream.closed:stream.close()
        wrong=subprocess.run([str(args.issuer),'--supervisor-pid',str(os.getpid()+1000000)],input=json.dumps(request),
                             capture_output=True,text=True,timeout=5)
        assert wrong.returncode==1 and json.loads(wrong.stdout)['code']=='owner_unavailable'
        report['wrongOwnerRejected']=True
        # Keep the inherited stdin writer alive in this parent, so owner death
        # cannot masquerade as ordinary stdin EOF. Adopt/reap the orphan ourselves.
        assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
        read_fd,write_fd=os.pipe()
        owner_code="""import json,os,subprocess,sys
p=subprocess.Popen([sys.argv[1],'--supervisor-pid',str(os.getpid())],stdin=int(sys.argv[2]),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(json.dumps({'pid':p.pid}),flush=True)
sys.stdin.read()
"""
        owner=subprocess.Popen([sys.executable,'-c',owner_code,str(args.issuer),str(read_fd)],stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,pass_fds=(read_fd,))
        os.close(read_fd)
        child_fd=None
        child_pid=None
        try:
            assert select.select([owner.stdout],[],[],10)[0]
            child_pid=json.loads(owner.stdout.readline())['pid']
            child_fd=os.pidfd_open(child_pid)
            wait_stdin_select(child_pid)
            owner.kill();owner.wait(timeout=5)
            poll=select.poll();poll.register(child_fd,select.POLLIN)
            assert poll.poll(5000), 'Helper survived its owner while stdin stayed open'
            reaped,status=os.waitpid(child_pid,0)
            assert reaped==child_pid and os.WIFEXITED(status) and os.WEXITSTATUS(status)==1
            child_pid=None
            report['ownerDeathWithOpenStdin']=dict(status='passed',helperReaped=True)
        finally:
            os.close(write_fd)
            retire(owner)
            if child_pid is not None and child_fd is not None:
                try:signal.pidfd_send_signal(child_fd,signal.SIGKILL)
                except ProcessLookupError:pass
                os.waitpid(child_pid,0)
            if child_fd is not None:os.close(child_fd)
            for stream in (owner.stdin,owner.stdout,owner.stderr):
                if stream and not stream.closed:stream.close()
        report['status']='passed'
        (args.evidence/'helper-summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
