import hashlib,hmac,json,os,select,socket,struct,subprocess,zlib,sys
from pathlib import Path
BINARY=str(Path(sys.argv[1]).resolve())
COOKIE=0x2112a442

def attribute(tag,value):return struct.pack('!HH',tag,len(value))+value+b'\0'*((-len(value))%4)
def request(credentials,valid=True):
    tx=os.urandom(12)
    attrs=attribute(6,(credentials['ufrag']+':remoteprobe').encode())+attribute(0x24,struct.pack('!I',2130706431))+attribute(0x802a,struct.pack('!Q',123456789))+attribute(0x25,b'')
    header=struct.pack('!HHI12s',1,len(attrs)+24,COOKIE,tx)
    key=credentials['password'].encode() if valid else b'wrong-private-fixture-key'
    integrity=attribute(8,hmac.new(key,header+attrs,hashlib.sha1).digest())
    header=struct.pack('!HHI12s',1,len(attrs)+24+8,COOKIE,tx)
    packet=header+attrs+integrity
    return packet+attribute(0x8028,struct.pack('!I',zlib.crc32(packet)^0x5354554e)),tx

def response(sock,target,credentials,valid=True):
    data,tx=request(credentials,valid);sock.sendto(data,('127.0.0.1',target))
    import time
    deadline=time.monotonic()+1
    while time.monotonic()<deadline:
        if not select.select([sock],[],[],max(0,deadline-time.monotonic()))[0]:break
        data,address=sock.recvfrom(65536)
        if address==('127.0.0.1',target) and len(data)>=20 and data[8:20]==tx:
            return dict(type=struct.unpack('!H',data[:2])[0],bytes=len(data))
    return None
with socket.socket(type=socket.SOCK_DGRAM) as granted,socket.socket(type=socket.SOCK_DGRAM) as other,socket.socket(type=socket.SOCK_DGRAM) as reservation:
    for sock in (granted,other,reservation):sock.bind(('127.0.0.1',0))
    target=reservation.getsockname()[1];reservation.close()
    for policy in (False,True):
        process=subprocess.Popen([BINARY,str(target),str(granted.getsockname()[1])]+(['guard'] if policy else []),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            assert select.select([process.stdout],[],[],5)[0],'No native gathering result'
            credentials=json.loads(process.stdout.readline())
            positive=response(granted,target,credentials);assert positive and positive['type']==0x101,positive
            wrong=response(other,target,credentials,False)
            unknown=response(other,target,credentials)
            again=response(granted,target,credentials);assert again and again['type']==0x101,again
            assert (unknown is None) if policy else (unknown and unknown['type']==0x101),unknown
            assert (wrong is None) if policy else (wrong and wrong['type']==0x111),wrong
            result=dict(peerPolicyEnabled=policy,scope='Private numeric loopback pinned NiceAgent; no deployed app exposure',knownGrantedBindingSuccess=True,unknownPortAuthenticatedReply=unknown,wrongKeyReply=wrong,configuredRemotePort=granted.getsockname()[1],unadvertisedSourcePort=other.getsockname()[1])
            print(json.dumps(result))
        finally:
            process.stdin.close();process.stdin=None
            stdout,stderr=process.communicate(timeout=5)
            assert process.returncode==0,(process.returncode,stderr)
