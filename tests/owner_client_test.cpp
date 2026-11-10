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
 return struct.pack('!I',len(body))+body
def state():
 return {'supervisorPid':os.getpid()+int(mode=='wrong-pid'),'instance':'owned-synthetic',
 'observedMonotonicMs':int(time.monotonic()*1000)-(10000 if mode=='stale' else 0),'stage':'sharing','phase':'ready'}
initial={'schemaVersion':2 if mode=='version' else 1,'event':'state','state':state()}
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
   if mode=='wrong-request':reply['requestId']+=100
   s.sendall(frame(reply))
except (BrokenPipeError,ConnectionResetError):pass
)PY";
        return file(prefix+"/bin/traverse",prepare)&&file(prefix+"/libexec/traverse/traverse-launcher",producer);
    }
  private slots:
    void liveStatusAndRefresh() {
        QTemporaryDir root;QVERIFY(root.isValid());QVERIFY(fixture(root.path(),"fragmented"));
        traverse::OwnerClient client(root.path(),"unused");
        int states=0;bool failed=false,refreshed=false,stopped=false;
        client.stateChanged=[&](const QJsonObject &state){if(!state.isEmpty())++states;};
        client.failed=[&](const QString &){failed=true;};
        client.codeRefreshed=[&](bool ok){refreshed=ok;};
        client.stopped=[&](int code){stopped=code==0;};
        client.start();QTRY_VERIFY_WITH_TIMEOUT(states>=3,3000);QVERIFY(!failed);
        client.newCode();QTRY_VERIFY_WITH_TIMEOUT(refreshed,2000);
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
