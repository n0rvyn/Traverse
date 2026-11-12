#ifndef Q_MOC_RUN
#include "setup_window.hpp"
#endif
#include <QComboBox>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTemporaryDir>
#include <QTest>
#include <QThread>
#include <QSignalSpy>
#include <QApplication>
#include <QScreen>
#include <QProcess>
#include <QScrollArea>
#include <QScrollBar>
#include <QFileDialog>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <sys/stat.h>
#include <thread>
using namespace traverse;
class SetupWindowTests:public QObject {
    Q_OBJECT
    static QPushButton *start(SetupWindow &window){return window.findChild<QPushButton*>("startSharing");}
    static void hostname(SetupWindow &window){window.findChild<QLineEdit*>("hostnameField")->setText("desktop.example.test");}
  private slots:
    void defaultsAndCloseHaveNoSideEffects() {
        QTemporaryDir root;QVERIFY(root.isValid());auto path=root.path()+"/traverse/config.json";
        SetupWindow window(path);window.show();QCOMPARE(window.findChild<QLineEdit*>("portField")->text(),QString("443"));
        QCOMPARE(window.findChild<QComboBox*>("certificateMethod")->currentData().toString(),QString("local"));
        QVERIFY(window.findChild<QLineEdit*>("hostnameField")->text().isEmpty());window.close();QVERIFY(!QFile::exists(root.path()+"/traverse"));
    }
    void confirmedStartCreatesAndHandsOff() {
        QTemporaryDir root;QVERIFY(root.isValid());auto path=root.path()+"/traverse/config.json";
        SetupWindow window(path);bool handed=false;window.configured=[&](const QString &file){handed=file==path;};window.show();hostname(window);
        auto screenshot=qEnvironmentVariable("TRAVERSE_TEST_SETUP_SCREENSHOT");if(!screenshot.isEmpty())QVERIFY(window.grab().save(screenshot));
        QTest::mouseClick(start(window),Qt::LeftButton);QTRY_VERIFY(handed);
        ConfigurationStore store(path.toStdString());auto saved=store.read();QVERIFY(saved.document.at("port")==443);QVERIFY(saved.document.at("certificateSettings").at("mode")=="local");
        QVERIFY(saved.document.at("domain")=="desktop.example.test");struct stat metadata{};QVERIFY(!stat(path.toUtf8().constData(),&metadata));QCOMPARE(int(metadata.st_mode&0777),0600);
        QVERIFY(!QFile::exists(root.path()+"/traverse/certificates"));
    }
    void initialWindowFitsAvailableScreen() {
        QTemporaryDir root;QVERIFY(root.isValid());SetupWindow window(root.path()+"/config.json");window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        auto screenshot=qEnvironmentVariable("TRAVERSE_TEST_SCALED_SETUP_SCREENSHOT");
        if(!screenshot.isEmpty())QVERIFY(window.screen()->grabWindow(0).save(screenshot));
        auto available=window.screen()->availableGeometry();
        QVERIFY2(window.width()<=available.width()&&window.height()<=available.height(),"Setup exceeds the available logical screen size");
        QVERIFY(available.contains(QRect(start(window)->mapToGlobal(QPoint(0,0)),start(window)->size())));
        auto method=window.findChild<QComboBox*>("certificateMethod");method->setCurrentIndex(method->findData("supplied"));
        QCoreApplication::processEvents();
        QVERIFY(available.contains(QRect(start(window)->mapToGlobal(QPoint(0,0)),start(window)->size())));
        auto fields=window.findChild<QScrollArea*>("setupFields");QVERIFY(fields);
        QCOMPARE(fields->horizontalScrollBar()->maximum(),0);
        if(window.screen()->availableGeometry().width()<=320) {
            auto certificate=window.findChild<QLineEdit*>("certificateField");
            QTRY_VERIFY(certificate->mapTo(fields->widget(),QPoint(0,0)).x()<fields->widget()->width()/4);
        }
        auto key=window.findChild<QLineEdit*>("privateKeyField");
        QTRY_VERIFY(([&]{fields->ensureWidgetVisible(key);return fields->viewport()->rect().contains(QRect(key->mapTo(fields->viewport(),QPoint(0,0)),key->size()));})());
        QCoreApplication::processEvents();
        if(!screenshot.isEmpty())QVERIFY(window.screen()->grabWindow(0).save(screenshot+".supplied.png"));
    }
    void suppliedCertificateFormCreatesVerifiedSettings() {
        QTemporaryDir root;QVERIFY(root.isValid());auto certificate=root.path()+"/certificate.pem",key=root.path()+"/key.pem";
        QProcess openssl;openssl.setStandardOutputFile(QProcess::nullDevice());openssl.setStandardErrorFile(QProcess::nullDevice());
        openssl.start("/usr/bin/openssl",{"req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-batch","-days","1",
            "-subj","/CN=desktop.example.test","-addext","subjectAltName=DNS:desktop.example.test","-keyout",key,"-out",certificate});
        QVERIFY(openssl.waitForFinished(15000));QCOMPARE(openssl.exitCode(),0);
        struct Restore {QByteArray previous=qgetenv("SSL_CERT_FILE");~Restore(){if(previous.isNull())qunsetenv("SSL_CERT_FILE");else qputenv("SSL_CERT_FILE",previous);}} restore;
        qputenv("SSL_CERT_FILE",certificate.toUtf8());auto path=root.path()+"/config.json";SetupWindow window(path);bool created=false;
        window.configured=[&](const QString&){created=true;};window.show();hostname(window);
        auto method=window.findChild<QComboBox*>("certificateMethod");method->setCurrentIndex(method->findData("supplied"));
        window.findChild<QLineEdit*>("certificateField")->setText("certificate.pem");window.findChild<QLineEdit*>("privateKeyField")->setText("key.pem");
        QTest::mouseClick(start(window),Qt::LeftButton);QTRY_VERIFY2(created,qPrintable(window.findChild<QLabel*>("setupFeedback")->text()));
        ConfigurationStore store(path.toStdString());auto saved=store.read().document;QVERIFY(!saved.contains("certificateSettings"));
        QVERIFY(saved.at("certificate")=="certificate.pem"&&saved.at("privateKey")=="key.pem");
    }
    void suppliedFilePickerResolvesRelativePathsAndCancels() {
        QTemporaryDir root;QVERIFY(root.isValid());
        QFile certificate(root.path()+"/certificate.pem");QVERIFY(certificate.open(QIODevice::WriteOnly));
        QVERIFY(certificate.write("Public file picker fixture")>0);certificate.close();
        SetupWindow window(root.path()+"/config.json");window.show();
        auto method=window.findChild<QComboBox*>("certificateMethod");method->setCurrentIndex(method->findData("supplied"));
        auto field=window.findChild<QLineEdit*>("certificateField");field->setText("certificate.pem");
        auto browse=window.findChild<QPushButton*>("certificateFieldBrowse");QTest::mouseClick(browse,Qt::LeftButton);
        auto picker=window.findChild<QFileDialog*>("certificateFieldPicker");QVERIFY(picker);QTRY_VERIFY(picker->isVisible());
        QCOMPARE(picker->directory().absolutePath(),root.path());picker->reject();
        QCOMPARE(field->text(),QString("certificate.pem"));
        QTRY_VERIFY(window.findChild<QFileDialog*>("certificateFieldPicker")==nullptr);
        QTest::mouseClick(browse,Qt::LeftButton);picker=window.findChild<QFileDialog*>("certificateFieldPicker");QVERIFY(picker);
        picker->selectFile(certificate.fileName());QVERIFY(QMetaObject::invokeMethod(picker,"accept",Qt::DirectConnection));
        QTRY_COMPARE(field->text(),certificate.fileName());QVERIFY(!QFile::exists(root.path()+"/config.json"));
    }
    void uncertainCreationNeverLaunchesOrClaimsSuccess() {
        struct Failure:ConfigurationIo {
            int sync(int fd) const override {
                struct stat metadata{};if(!fstat(fd,&metadata)&&S_ISDIR(metadata.st_mode)){errno=EIO;return -1;}
                return ConfigurationIo::sync(fd);
            }
        };
        QTemporaryDir root;QVERIFY(root.isValid());auto path=root.path()+"/config.json";SetupWindow window(path,nullptr,std::make_shared<Failure>());
        bool launched=false;window.configured=[&](const QString&){launched=true;};window.show();hostname(window);QTest::mouseClick(start(window),Qt::LeftButton);
        QTRY_VERIFY(window.findChild<QLabel*>("setupFeedback")->text().startsWith("Cannot confirm setup."));
        QVERIFY(!launched&&!start(window)->isEnabled());ConfigurationStore observed(path.toStdString());QVERIFY(observed.read().document.at("domain")=="desktop.example.test");
    }
    void invalidInputAndExistingFileAreNotOverwritten() {
        QTemporaryDir root;QVERIFY(root.isValid());auto path=root.path()+"/config.json";
        SetupWindow window(path);bool handed=false;window.configured=[&](const QString&){handed=true;};window.show();
        QTest::mouseClick(start(window),Qt::LeftButton);QVERIFY(window.findChild<QLabel*>("hostnameFieldError")->isVisible());QVERIFY(!QFile::exists(path));
        QFile original(path);QVERIFY(original.open(QIODevice::WriteOnly));QVERIFY(original.write("existing invalid JSON")>0);original.close();
        hostname(window);QTest::mouseClick(start(window),Qt::LeftButton);QTRY_VERIFY(window.findChild<QLabel*>("setupFeedback")->text().contains("already exist"));
        QVERIFY(!handed);QVERIFY(original.open(QIODevice::ReadOnly));QCOMPARE(original.readAll(),QByteArray("existing invalid JSON"));
    }
    void closedDuringCreationKeepsCommittedFileWithoutLaunch() {
        struct Block:ConfigurationIo {
            mutable std::atomic<bool> entered{false},release{false},published{false};
            mutable std::atomic<QThread*> worker{nullptr};
            ssize_t write(int fd,const void *bytes,size_t count) const override {
                worker=QThread::currentThread();entered=true;while(!release.load())std::this_thread::sleep_for(std::chrono::milliseconds(5));
                return ConfigurationIo::write(fd,bytes,count);
            }
            int publishNew(int directory,const char *source,const char *destination) const override {
                auto result=ConfigurationIo::publishNew(directory,source,destination);published=!result;return result;
            }
        };
        QTemporaryDir root;QVERIFY(root.isValid());auto path=root.path()+"/config.json";auto io=std::make_shared<Block>();
        SetupWindow window(path,nullptr,io);bool launched=false;window.configured=[&](const QString&){launched=true;};window.show();hostname(window);
        QTest::mouseClick(start(window),Qt::LeftButton);QTRY_VERIFY(io->entered.load());QElapsedTimer time;time.start();window.close();QVERIFY(time.elapsed()<100);
        QSignalSpy finished(io->worker.load(),&QThread::finished);
        io->release=true;QTRY_COMPARE(finished.count(),1);QVERIFY(io->published.load());
        // Wait for the completed worker's GUI delivery before judging suppression.
        QTRY_VERIFY(QFile::exists(path));ConfigurationStore store(path.toStdString());QVERIFY(store.read().document.at("domain")=="desktop.example.test");
        QCoreApplication::sendPostedEvents();QCoreApplication::processEvents();QVERIFY(!launched);
    }
};
QTEST_MAIN(SetupWindowTests)
#include "setup_window_test.moc"
