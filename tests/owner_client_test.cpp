#include "owner_client.hpp"
#include <QDir>
#include <QFile>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTest>

class OwnerClientTests:public QObject {
    Q_OBJECT
    static bool file(const QString &path,const QByteArray &bytes) {
        QFile target(path);
        return target.open(QIODevice::WriteOnly)&&target.write(bytes)==bytes.size()&&
            target.setPermissions(QFile::ReadOwner|QFile::WriteOwner|QFile::ExeOwner);
    }
    static bool fixture(const QString &prefix,const QString &mode) {
        if(!QDir().mkpath(prefix+"/bin")||!QDir().mkpath(prefix+"/libexec/traverse"))return false;
        QByteArray prepare="#!/usr/bin/python3\nimport json\nprint(json.dumps({'schemaVersion':1,'environment':{'TRAVERSE_RUNTIME_PREFIX':"+
            QByteArray("'")+prefix.toUtf8()+"'}}))\n";
        QByteArray producer=R"PY(#!/usr/bin/python3
import json,os,socket,struct,sys,time
mode=')PY"+mode.toUtf8()+R"PY('
fd=int(sys.argv[sys.argv.index('--owner-fd')+1]);s=socket.socket(fileno=fd)
s.setblocking(True)
def frame(value):
 body=json.dumps(value,separators=(',',':')).encode()
 if mode=='duplicate':body=body.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1',1)
 if mode=='export-duplicate' and 'publicCA' in value:body=body.replace(b'"domain":"desktop.example.test"',b'"domain":"desktop.example.test","domain":"desktop.example.test"')
 return struct.pack('!I',len(body))+body
def public_ca():
 return {'version':1,'domain':'desktop.example.test','pem':'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n','fingerprint':'a'*64,'validFrom':int(time.time())-60,'validUntil':int(time.time())+3600}
def state():
 return {'supervisorPid':os.getpid()+int(mode=='wrong-pid'),'instance':'owned-synthetic',
 'observedMonotonicMs':int(time.monotonic()*1000)-(10000 if mode=='stale' else 0),'stage':'sharing','phase':'ready'}
initial={'schemaVersion':2 if mode=='version' else 1,'event':'state','state':state()}
if mode=='export-unsolicited':initial['publicCA']=public_ca()
if mode=='missing-instance':initial['state'].pop('instance')
if mode=='nested-duplicate':
 body=json.dumps(initial,separators=(',',':')).replace('"phase":"ready"','"phase":"ready","phase":"ready"').encode()
 payload=struct.pack('!I',len(body))+body
else:payload=frame(initial)
try:
 if mode=='fragmented':
  for byte in payload:s.sendall(bytes([byte]))
 else:s.sendall(payload)
 incoming=b''
 while True:
  block=s.recv(4096)
  if not block:break
  incoming+=block
  while len(incoming)>=4:
   size=struct.unpack('!I',incoming[:4])[0]
   if len(incoming)<size+4:break
   command=json.loads(incoming[4:4+size]);incoming=incoming[4+size:]
   reply={'schemaVersion':1,'requestId':command['requestId'],'ok':True,'state':state()}
   if command['action']=='export-ca':
    reply['publicCA']=public_ca()
    if mode=='export-stale':reply['state']['observedMonotonicMs']-=10000
    if mode=='export-version':reply['publicCA']['version']=2
    if mode=='export-key':reply['publicCA']['pem']='-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'
    if mode=='export-extra':reply['publicCA']['unknown']=True
    if mode=='export-instance':reply['state']['instance']='unexpected-owner'
    if mode=='export-request':reply['requestId']+=100
    if mode=='export-no-state':reply.pop('state')
    if mode=='export-failed-data':reply['ok']=False
    if mode=='export-denied':reply['ok']=False;reply.pop('publicCA')
    if mode=='export-eof':s.close();sys.exit(0)
   if mode=='wrong-request':reply['requestId']+=100
   s.sendall(frame(reply))
except (BrokenPipeError,ConnectionResetError):pass
)PY";
        return file(prefix+"/bin/traverse",prepare)&&file(prefix+"/libexec/traverse/traverse-launcher",producer);
    }
  private slots:
    void correlatedPublicOnlyExport() {
        QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),"export-good"));
        traverse::OwnerClient client(root.path(),"unused");int states=0;bool exported=false,failed=false,stopped=false;
        client.stateChanged=[&](const QJsonObject &value){if(!value.isEmpty())++states;};
        client.failed=[&](const QString &){failed=true;};
        client.stopped=[&](int){stopped=true;};
        client.publicCAExported=[&](bool ok,const QJsonObject &value,const QJsonObject &state){exported=ok&&value.value("domain").toString()=="desktop.example.test"&&state.value("instance").toString()=="owned-synthetic";};
        client.start();QTRY_VERIFY(states>0);client.exportCA();QTRY_VERIFY(exported);QVERIFY(!failed);client.stop();QTRY_VERIFY(stopped);
    }
    void rejectsInvalidPublicExport_data() {
        QTest::addColumn<QString>("mode");QTest::addColumn<bool>("protocolFailure");
        for(const char *mode:{"export-version","export-key","export-extra","export-instance","export-request","export-no-state","export-failed-data","export-duplicate"})
            QTest::newRow(mode)<<QString(mode)<<true;
        for(const char *mode:{"export-stale","export-denied","export-eof"})QTest::newRow(mode)<<QString(mode)<<false;
    }
    void rejectsInvalidPublicExport() {
        QFETCH(QString,mode);QFETCH(bool,protocolFailure);QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),mode));
        traverse::OwnerClient client(root.path(),"unused");int states=0;bool delivered=false,rejected=false,failed=false,stopped=false;
        client.stateChanged=[&](const QJsonObject &value){if(!value.isEmpty())++states;};client.failed=[&](const QString&){failed=true;};client.stopped=[&](int){stopped=true;};
        client.publicCAExported=[&](bool ok,const QJsonObject &value,const QJsonObject &state){Q_UNUSED(state);delivered=ok;rejected=!ok&&value.isEmpty();};
        client.start();QTRY_VERIFY(states>0);client.exportCA();QTRY_VERIFY(rejected);QVERIFY(!delivered);
        if(protocolFailure)QTRY_VERIFY(failed);else QVERIFY(!failed);
        client.stop();QTRY_VERIFY(stopped);
    }
    void unsolicitedPublicDataIsRejected() {
        QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),"export-unsolicited"));
        traverse::OwnerClient client(root.path(),"unused");bool failed=false,delivered=false,stopped=false;
        client.failed=[&](const QString&){failed=true;};client.publicCAExported=[&](bool ok,const QJsonObject&,const QJsonObject&){delivered=ok;};client.stopped=[&](int){stopped=true;};
        client.start();QTRY_VERIFY(failed);QVERIFY(!delivered);QTRY_VERIFY(stopped);
    }
    void liveStatusAndRefresh() {
        QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),"fragmented"));
        traverse::OwnerClient client(root.path(),"unused");
        int states=0;bool failed=false,refreshed=false,stopped=false,checked=false;
        client.stateChanged=[&](const QJsonObject &state){if(!state.isEmpty())++states;};
        client.failed=[&](const QString &){failed=true;};
        client.codeRefreshed=[&](bool ok){refreshed=ok;};
        client.connectionCheckRequested=[&](bool ok){checked=ok;};
        client.stopped=[&](int code){stopped=code==0;};
        client.start();QTRY_VERIFY_WITH_TIMEOUT(states>=3,3000);QVERIFY(!failed);
        client.newCode();QTRY_VERIFY_WITH_TIMEOUT(refreshed,2000);
        client.checkConnection();QTRY_VERIFY_WITH_TIMEOUT(checked,2000);
        client.stop();QTRY_VERIFY_WITH_TIMEOUT(stopped,2000);QVERIFY(!failed);
    }
    void rejectsInvalidProducer_data() {
        QTest::addColumn<QString>("mode");
        for(const char *mode:{"wrong-pid","version","duplicate","nested-duplicate","missing-instance","wrong-request"})
            QTest::newRow(mode)<<QString(mode);
    }
    void rejectsInvalidProducer() {
        QFETCH(QString,mode);QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),mode));
        traverse::OwnerClient client(root.path(),"unused");
        bool failed=false,stopped=false;
        client.failed=[&](const QString &){failed=true;};client.stopped=[&](int){stopped=true;};
        client.start();QTRY_VERIFY_WITH_TIMEOUT(failed,2500);
        QTRY_VERIFY_WITH_TIMEOUT(stopped,2500);
    }
    void staleStateDoesNotRevokeOwner() {
        QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),"stale"));
        traverse::OwnerClient client(root.path(),"unused");
        int unavailable=0;bool failed=false,stopped=false;
        client.stateChanged=[&](const QJsonObject &state){if(state.isEmpty())++unavailable;};
        client.failed=[&](const QString &){failed=true;};client.stopped=[&](int){stopped=true;};
        client.start();QTRY_VERIFY_WITH_TIMEOUT(unavailable>=3,2500);
        QVERIFY(!failed);QVERIFY(!stopped);
        client.stop();QTRY_VERIFY_WITH_TIMEOUT(stopped,2000);
    }
};
QTEST_GUILESS_MAIN(OwnerClientTests)
#include "owner_client_test.moc"
