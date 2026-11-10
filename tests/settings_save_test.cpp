#ifndef Q_MOC_RUN
#include "configuration_store.hpp"
#include "endpoint_settings.hpp"
#endif
#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QTest>
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace traverse;
using Json=nlohmann::json;
struct FaultIo:ConfigurationIo {
    enum Mode {None,Partial,Write,FileSync,DirectorySync,Replace,Readback};
    Mode mode=None;
    mutable bool replaced=false;
    ssize_t write(int fd,const void *data,size_t count) const override {
        if(mode==Write){errno=ENOSPC;return -1;}
        return ConfigurationIo::write(fd,data,mode==Partial?std::min(count,size_t(3)):count);
    }
    int sync(int fd) const override {
        struct stat item{};
        if(fstat(fd,&item))return -1;
        if((mode==FileSync&&S_ISREG(item.st_mode))||(mode==DirectorySync&&S_ISDIR(item.st_mode))){errno=EIO;return -1;}
        return ConfigurationIo::sync(fd);
    }
    int replace(int directory,const char *temporary,const char *destination) const override {
        if(mode==Replace){errno=EIO;return -1;}
        auto result=ConfigurationIo::replace(directory,temporary,destination);replaced=!result;return result;
    }
    int openRead(int directory,const char *name) const override {
        if(mode==Readback&&replaced){errno=EIO;return -1;}
        return ConfigurationIo::openRead(directory,name);
    }
};
class SettingsSaveTests:public QObject {
    Q_OBJECT
    std::unique_ptr<QTemporaryDir> root;
    std::filesystem::path path;
    Json original;
    static bool bytes(const QString &path,const QByteArray &value) {
        QFile file(path);return file.open(QIODevice::WriteOnly|QIODevice::Truncate)&&file.write(value)==value.size()&&
            file.setPermissions(QFile::ReadOwner|QFile::WriteOwner);
    }
    QByteArray contents() const {QFile file(QString::fromStdString(path.string()));if(!file.open(QIODevice::ReadOnly))return {};return file.readAll();}
    bool noTemporary() const {
        return QDir(root->path()).entryList({".traverse-settings-*"},QDir::Files|QDir::Hidden).isEmpty();
    }
  private slots:
    void init() {
        root=std::make_unique<QTemporaryDir>();QVERIFY(root->isValid());
        path=(root->path()+"/config.json").toStdString();
        QProcess openssl;openssl.setStandardOutputFile(QProcess::nullDevice());openssl.setStandardErrorFile(QProcess::nullDevice());
        openssl.start("/usr/bin/openssl",{"req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-batch","-days","1",
            "-subj","/CN=settings.example.test","-addext","subjectAltName=DNS:settings.example.test,DNS:other.settings.example.test",
            "-keyout",root->path()+"/key.pem","-out",root->path()+"/certificate.pem"});
        QVERIFY(openssl.waitForFinished(15000));QCOMPARE(openssl.exitCode(),0);
        // Trust only this synthetic certificate inside this test process.
        // Production chain verification remains the existing shared validator.
        qputenv("SSL_CERT_FILE",(root->path()+"/certificate.pem").toUtf8());
        original={{"schemaVersion",1},{"domain","settings.example.test"},{"port",443},{"basePath","/traverse/"},
            {"display",":99"},{"certificate","certificate.pem"},{"privateKey","key.pem"}};
        QVERIFY(bytes(QString::fromStdString(path.string()),QByteArray::fromStdString(original.dump(2)+"\n")));
    }
    void saveReadbackAndNextLaunch() {
        ConfigurationStore store(path);auto base=store.read();
        QVERIFY(!QFile::exists(root->path()+"/.config.json.lock"));
        auto draft=base.document;draft["port"]=9443;draft["domain"]="other.settings.example.test";
        auto result=store.save(base,draft);QVERIFY2(result.outcome==SaveOutcome::Saved,result.detail.c_str());QVERIFY(result.verified.has_value());
        QVERIFY(base.document==original);QVERIFY(result.verified->document==draft);
        ConfigurationStore reopened(path);auto next=reopened.read();
        QVERIFY(next.document==draft);
        auto endpoint=EndpointSettings::parse(next.document,"",root->path().toStdString());
        QVERIFY(endpoint.public_url()=="https://other.settings.example.test:9443/traverse/");
        QVERIFY(endpoint.certificates.certificate==(root->path()+"/certificate.pem").toStdString());
        struct stat saved{};QVERIFY(!stat(path.c_str(),&saved));QCOMPARE(int(saved.st_mode&0777),0600);QVERIFY(noTemporary());
    }
    void invalidDraftPreservesExactOldBytes() {
        ConfigurationStore store(path);auto base=store.read();auto before=contents();
        for(int scenario:{0,1,2,3}) {
            auto draft=original;
            if(scenario==0)draft["port"]=22;
            if(scenario==1)draft["domain"]="invalid/domain";
            if(scenario==2)draft["privateKey"]="missing-key.pem";
            if(scenario==3)draft["schemaVersion"]=2;
            auto result=store.save(base,draft);QVERIFY(result.outcome==SaveOutcome::NotSaved);
            QVERIFY(result.problem==ConfigurationProblem::Validation);QVERIFY(!result.verified);QVERIFY(contents()==before);
        }
        QVERIFY(noTemporary());
    }
    void untrustedCertificateIsRejected() {
        ConfigurationStore store(path);auto base=store.read();auto before=contents();
        qunsetenv("SSL_CERT_FILE");auto result=store.save(base,original);
        qputenv("SSL_CERT_FILE",(root->path()+"/certificate.pem").toUtf8());
        QVERIFY(result.outcome==SaveOutcome::NotSaved);QVERIFY(result.problem==ConfigurationProblem::Validation);
        QVERIFY(contents()==before);QVERIFY(noTemporary());
    }
    void partialWritesAndPrecommitIoFailure_data() {
        QTest::addColumn<int>("mode");
        QTest::newRow("partial writes")<<int(FaultIo::Partial);
        QTest::newRow("disk full")<<int(FaultIo::Write);
        QTest::newRow("file sync error")<<int(FaultIo::FileSync);
    }
    void partialWritesAndPrecommitIoFailure() {
        QFETCH(int,mode);auto io=std::make_shared<FaultIo>();ConfigurationStore store(path,io);
        auto base=store.read();auto before=contents();auto draft=original;draft["port"]=9443;io->mode=FaultIo::Mode(mode);
        auto result=store.save(base,draft);
        if(mode==FaultIo::Partial){QVERIFY(result.outcome==SaveOutcome::Saved);QVERIFY(result.verified->document==draft);}
        else {QVERIFY(result.outcome==SaveOutcome::NotSaved);QVERIFY(contents()==before);QVERIFY(!result.verified);}
        QVERIFY(noTemporary());
    }
    void uncertainCommitRequiresReconciliation_data() {
        QTest::addColumn<int>("mode");
        QTest::newRow("rename error")<<int(FaultIo::Replace);
        QTest::newRow("directory sync error")<<int(FaultIo::DirectorySync);
        QTest::newRow("readback error")<<int(FaultIo::Readback);
    }
    void uncertainCommitRequiresReconciliation() {
        QFETCH(int,mode);auto io=std::make_shared<FaultIo>();ConfigurationStore store(path,io);
        auto base=store.read();auto before=contents();auto draft=original;draft["port"]=9443;io->mode=FaultIo::Mode(mode);
        auto result=store.save(base,draft);QVERIFY(result.outcome==SaveOutcome::Uncertain);QVERIFY(!result.verified);
        if(mode==FaultIo::Replace)QVERIFY(contents()==before);else QVERIFY(Json::parse(contents().toStdString())==draft);
        auto denied=store.save(base,draft);QVERIFY(denied.problem==ConfigurationProblem::ReconcileRequired);
        io->mode=FaultIo::None;auto actual=store.read();auto next=actual.document;next["port"]=10443;
        QVERIFY(store.save(actual,next).outcome==SaveOutcome::Saved);QVERIFY(noTemporary());
    }
    void unsafeOrChangedDestinationIsPreserved() {
        ConfigurationStore store(path);auto base=store.read();auto draft=original;draft["port"]=9443;
        auto externally_changed=original;externally_changed["port"]=8443;
        QVERIFY(bytes(QString::fromStdString(path.string()),QByteArray::fromStdString(externally_changed.dump())));
        auto changed=contents();QVERIFY(store.save(base,draft).problem==ConfigurationProblem::Changed);QVERIFY(contents()==changed);
        auto current=store.read();QVERIFY(!chmod(path.c_str(),0400));
        QVERIFY(store.save(current,draft).outcome==SaveOutcome::NotSaved);QVERIFY(contents()==changed);
        QVERIFY(!chmod(path.c_str(),0600));auto sentinel=root->path()+"/sentinel";QVERIFY(bytes(sentinel,"unrelated-owned-data"));
        QVERIFY(!unlink(path.c_str()));QVERIFY(!symlink(sentinel.toStdString().c_str(),path.c_str()));
        QVERIFY(store.save(current,draft).outcome==SaveOutcome::NotSaved);
        QFile file(sentinel);QVERIFY(file.open(QIODevice::ReadOnly));QVERIFY(file.readAll()=="unrelated-owned-data");QVERIFY(noTemporary());
    }
    void concurrentSaveLockDoesNotReplace() {
        ConfigurationStore store(path);auto base=store.read();auto before=contents();auto draft=original;draft["port"]=9443;
        auto lock=(root->path()+"/.config.json.lock").toStdString();int fd=open(lock.c_str(),O_CREAT|O_RDWR|O_CLOEXEC,0600);
        QVERIFY(fd>=0);QVERIFY(!flock(fd,LOCK_EX|LOCK_NB));
        auto result=store.save(base,draft);close(fd);QVERIFY(result.problem==ConfigurationProblem::Busy);QVERIFY(contents()==before);
    }
    void replacedParentCannotReportSaved() {
        struct RebindIo:ConfigurationIo {
            std::filesystem::path named,moved;
            std::string replacement;
            int replace(int directory,const char *temporary,const char *destination) const override {
                auto result=ConfigurationIo::replace(directory,temporary,destination);
                if(result)return result;
                std::filesystem::rename(named,moved);
                std::filesystem::create_directory(named);
                std::filesystem::permissions(named,std::filesystem::perms::owner_all);
                QFile file(QString::fromStdString((named/destination).string()));
                if(!file.open(QIODevice::WriteOnly)||file.write(QByteArray::fromStdString(replacement))<0)
                    throw std::runtime_error("Controlled replacement fixture failed");
                file.setPermissions(QFile::ReadOwner|QFile::WriteOwner);
                return 0;
            }
        };
        auto io=std::make_shared<RebindIo>();
        io->named=std::filesystem::path(root->path().toStdString())/"settings";
        io->moved=std::filesystem::path(root->path().toStdString())/"retired";
        std::filesystem::create_directory(io->named);
        auto configured=original;
        configured["certificate"]=(root->path()+"/certificate.pem").toStdString();
        configured["privateKey"]=(root->path()+"/key.pem").toStdString();
        auto actual_path=io->named/"config.json";
        QVERIFY(bytes(QString::fromStdString(actual_path.string()),QByteArray::fromStdString(configured.dump())));
        ConfigurationStore store(actual_path,io);auto base=store.read();auto draft=configured;draft["port"]=9443;
        auto replacement=configured;replacement["port"]=8443;io->replacement=replacement.dump();
        auto result=store.save(base,draft);
        QVERIFY(result.outcome==SaveOutcome::Uncertain);QVERIFY(!result.verified);
        QFile named(QString::fromStdString(actual_path.string()));QVERIFY(named.open(QIODevice::ReadOnly));
        QVERIFY(named.readAll()==QByteArray::fromStdString(io->replacement));
        QVERIFY(store.save(base,draft).problem==ConfigurationProblem::ReconcileRequired);
        auto actual=store.read();QVERIFY(actual.document==replacement);
    }
    void explicitAutomaticSettingsDoNotConnectOrEnroll() {
        int listener=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);QVERIFY(listener>=0);
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        QVERIFY(!bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)));QVERIFY(!listen(listener,1));
        socklen_t length=sizeof(address);QVERIFY(!getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length));
        ConfigurationStore store(path);auto base=store.read();auto automatic=original;
        automatic.erase("certificate");automatic.erase("privateKey");
        automatic["certificateSettings"]={{"mode","automatic"},{"directory","https://127.0.0.1:"+std::to_string(ntohs(address.sin_port))+"/directory"},
            {"termsURL",""},{"termsAgreed",false}};
        QVERIFY(store.save(base,automatic).outcome==SaveOutcome::NotSaved);
        automatic["certificateSettings"]["termsAgreed"]=true;
        QVERIFY(store.save(base,automatic).outcome==SaveOutcome::Saved);
        QVERIFY(accept(listener,nullptr,nullptr)<0);QVERIFY(errno==EAGAIN||errno==EWOULDBLOCK);
        int positive=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);QVERIFY(positive>=0);
        QVERIFY(!::connect(positive,reinterpret_cast<sockaddr*>(&address),sizeof(address)));
        int accepted=accept(listener,nullptr,nullptr);QVERIFY(accepted>=0);close(accepted);close(positive);close(listener);
        auto entries=QDir(root->path()).entryList(QDir::AllEntries|QDir::NoDotAndDotDot|QDir::Hidden);
        QVERIFY(entries.size()==4); // Config, existing certificate/key, owned save lock; no enrollment state.
    }
};
QTEST_GUILESS_MAIN(SettingsSaveTests)
#include "settings_save_test.moc"
