"""Actual Go CA -> independent shared C++/Qt verifier -> atomic public file.

Component/IO boundary tests. The owned-state envelope is synthetic; real owner
correlation and browser trust use separate end-to-end fixtures.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--probe',required=True,type=Path);parser.add_argument('--issuer',required=True,type=Path);args=parser.parse_args()
    assert os.geteuid()!=0, "Run the file-permission controls as the disposable desktop owner"
    os.umask(0o077);reports=[]
    with tempfile.TemporaryDirectory(prefix='public-codec-') as temporary:
        root=Path(temporary)
        for domain in ('desktop.example.test','xn--bcher-kva.de','127.0.0.1','::1','::ffff:192.0.2.1'):
            state=root/('authority-'+str(len(reports)))
            generated=subprocess.run([str(args.issuer),'--supervisor-pid',str(os.getpid())],input=json.dumps({'version':1,'operation':'local-ensure','domain':domain,'stateDirectory':str(state)}),capture_output=True,text=True,check=True,timeout=15)
            local=json.loads(generated.stdout)['local'];pem=(state/'local-ca.pem').read_text()
            try:
                ip=ipaddress.ip_address(domain);hostname=str(getattr(ip,'ipv4_mapped',None) or ip)
            except ValueError:hostname=domain
            host='['+hostname+']' if ':' in hostname else hostname
            certificate=dict(local['root'],version=1,domain=hostname,pem=pem)
            snapshot={'configuredUrl':'https://'+host+'/','localHttps':{'status':'passed'},'issuer':{'localAuthority':dict(local['root'],domain=hostname,available=True)}}
            sequence=0
            def run(ca=None,current=None,destination=None,cancelled=False):
                nonlocal sequence
                sequence+=1;output=destination or root/('export-'+str(len(reports))+'-'+str(sequence)+'.crt')
                request={'certificate':ca or certificate,'state':current or snapshot,'destination':str(output),'cancelled':cancelled}
                result=subprocess.run([str(args.probe)],input=json.dumps(request),capture_output=True,text=True,check=True,timeout=10)
                return json.loads(result.stdout),output
            result,output=run();assert result['ok'] and output.read_text()==pem
            assert b'PRIVATE KEY' not in output.read_bytes() and output.read_bytes().count(b'BEGIN CERTIFICATE')==1
            negatives=[]
            for kind in ('key-prefix','two-certificates','fingerprint','dates','domain','not-ready','extra-field','cancelled'):
                ca=copy.deepcopy(certificate);current=copy.deepcopy(snapshot)
                if kind=='key-prefix':ca['pem']='-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n'+pem
                elif kind=='two-certificates':ca['pem']+=pem
                elif kind=='fingerprint':ca['fingerprint']=current['issuer']['localAuthority']['fingerprint']='0'*64
                elif kind=='dates':ca['validUntil']+=1;current['issuer']['localAuthority']['validUntil']+=1
                elif kind=='domain':ca['domain']=current['issuer']['localAuthority']['domain']='other.example.test';current['configuredUrl']='https://other.example.test/'
                elif kind=='not-ready':current['localHttps']['status']='unknown'
                elif kind=='extra-field':ca['unknown']=True
                rejected,path=run(ca,current,cancelled=kind=='cancelled');assert not rejected['ok'] and not path.exists(),kind
                negatives.append(kind)
            # A failed atomic save must preserve a writable existing file when
            # its directory cannot hold a temporary; no direct-write fallback.
            readonly=root/('readonly-'+str(len(reports)));readonly.mkdir();existing=readonly/'retained.crt';existing.write_bytes(b'Preserve this existing file');readonly.chmod(0o500)
            try:
                rejected,_=run(destination=existing);assert not rejected['ok'] and existing.read_bytes()==b'Preserve this existing file'
            finally:readonly.chmod(0o700)
            if domain=='desktop.example.test':
                help_text=subprocess.run(['openssl','x509','-help'],capture_output=True,text=True,check=True).stderr
                assert '-preserve_dates' in help_text,'Actual OpenSSL CLI does not expose required date-preservation option'
                base=['basicConstraints=critical,CA:TRUE,pathlen:0','keyUsage=critical,keyCertSign,cRLSign','extendedKeyUsage=serverAuth',
                    'nameConstraints=critical,permitted;DNS:'+hostname+',excluded;DNS:.'+hostname+',excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0']
                for variant in ('control','broader-name','noncritical','client-auth','subca','root-san','expired'):
                    extensions=list(base)
                    if variant=='broader-name':extensions[3]=extensions[3].replace('permitted;DNS:'+hostname,'permitted;DNS:example.test')
                    elif variant=='noncritical':extensions[3]=extensions[3].replace('nameConstraints=critical,','nameConstraints=')
                    elif variant=='client-auth':extensions[2]+=',clientAuth'
                    elif variant=='subca':extensions[0]=extensions[0].replace('pathlen:0','pathlen:1')
                    elif variant=='root-san':extensions.append('subjectAltName=DNS:'+hostname)
                    configuration=root/(variant+'.extensions');configuration.write_text('\n'.join(extensions)+'\n');forged=root/(variant+'.pem')
                    command=['openssl','x509','-in',str(state/'local-ca.pem'),'-signkey',str(state/'local-authority.pem'),'-sha256','-clrext','-extfile',str(configuration),'-out',str(forged)]
                    command+=['-days','-1'] if variant=='expired' else ['-preserve_dates']
                    subprocess.run(command,capture_output=True,text=True,check=True,timeout=10)
                    ca=copy.deepcopy(certificate);current=copy.deepcopy(snapshot);ca['pem']=forged.read_text()
                    ca['fingerprint']=hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca['pem'])).hexdigest()
                    dates=subprocess.run(['openssl','x509','-in',str(forged),'-noout','-startdate','-enddate'],capture_output=True,text=True,check=True).stdout.splitlines()
                    ca['validFrom']=int(ssl.cert_time_to_seconds(dates[0].split('=',1)[1]));ca['validUntil']=int(ssl.cert_time_to_seconds(dates[1].split('=',1)[1]))
                    current['issuer']['localAuthority'].update({key:ca[key] for key in ('fingerprint','validFrom','validUntil')})
                    outcome,path=run(ca,current)
                    assert outcome['ok']==(variant=='control'),(variant,outcome)
                    assert path.exists()==(variant=='control')
                    if variant!='control':negatives.append('signed-'+variant)
            reports.append({'domain':domain,'actualGoRootAccepted':True,'certificateOnlyAtomicOutput':True,'existingFilePreservedOnSaveFailure':True,'negativeCases':negatives})
    print(json.dumps({'status':'passed','scope':'Actual Go-root/C++-Qt crypto and file boundary; synthetic state envelope, no browser/GUI or system trust claim','cases':reports}),flush=True)


if __name__=='__main__':main()
