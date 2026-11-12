#ifndef Q_MOC_RUN
#include "settings_dialog.hpp"
#include "endpoint_form.hpp"
#endif
#include <QComboBox>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTemporaryDir>
#include <QTest>
#include <QScreen>
#include <QScrollArea>
#include <QScrollBar>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>
using namespace traverse;
using Json=nlohmann::json;
struct DialogIo:ConfigurationIo {
    std::atomic<bool> hold{false},entered{false},finished{false};
    bool write_failure=false,uncertain=false;
    int openRead(int directory,const char *name) const override {
        auto self=const_cast<DialogIo*>(this);self->entered=true;
        while(hold.load())std::this_thread::sleep_for(std::chrono::milliseconds(5));
        int result=ConfigurationIo::openRead(directory,name);self->finished=true;return result;
    }
    ssize_t write(int fd,const void *data,size_t count) const override {
        if(write_failure){errno=ENOSPC;return -1;}return ConfigurationIo::write(fd,data,count);
    }
    int sync(int fd) const override {
        struct stat metadata{};
        if(uncertain&&!fstat(fd,&metadata)&&S_ISDIR(metadata.st_mode)){errno=EIO;return -1;}
        return ConfigurationIo::sync(fd);
    }
};
class SettingsDialogTests:public QObject {
    Q_OBJECT
    std::unique_ptr<QTemporaryDir> root;
    QString path;
    Json original;
    void write(const Json &value) {QFile file(path);QVERIFY(file.open(QIODevice::WriteOnly|QIODevice::Truncate));QVERIFY(file.write(QByteArray::fromStdString(value.dump()))>0);QVERIFY(file.setPermissions(QFile::ReadOwner|QFile::WriteOwner));}
    Json disk() {QFile file(path);if(!file.open(QIODevice::ReadOnly))return {};return Json::parse(file.readAll().toStdString());}
    static QLineEdit *port(SettingsDialog &dialog) {return dialog.findChild<QLineEdit*>("portField");}
    static QPushButton *save(SettingsDialog &dialog) {return dialog.findChild<QPushButton*>("saveSettings");}
    static QLabel *feedback(SettingsDialog &dialog) {return dialog.findChild<QLabel*>("saveFeedback");}
  private slots:
    void init() {
        root=std::make_unique<QTemporaryDir>();QVERIFY(root->isValid());path=root->path()+"/config.json";
        original={{"schemaVersion",1},{"domain","desktop.example.test"},{"port",443},{"basePath","/remote/"},
            {"display",":99"},{"listenAddress","127.0.0.1"},{"certificateSettings",{{"mode","local"}}}};
        write(original);
    }
    void actualSaveReadbackAndReopen() {
        SettingsDialog dialog(path);dialog.show();QTRY_VERIFY2(save(dialog)->isEnabled(),qPrintable(feedback(dialog)->text()));
        port(dialog)->setText("9443");QTest::mouseClick(save(dialog),Qt::LeftButton);
        QTRY_COMPARE(feedback(dialog)->text(),QString("Saved. Changes take effect the next time you launch Traverse."));
        auto expected=original;expected["port"]=9443;QVERIFY(disk()==expected);
        dialog.close();SettingsDialog reopened(path);reopened.show();QTRY_VERIFY(save(reopened)->isEnabled());QCOMPARE(port(reopened)->text(),QString("9443"));
        auto output=qEnvironmentVariable("TRAVERSE_TEST_SETTINGS_SCREENSHOT");
        if(!output.isEmpty())QVERIFY(reopened.grab().save(output));
    }
    void automaticAndNonVisibleFieldsPreserved() {
        original["certificateSettings"]={{"mode","automatic"},{"directory","https://ca.example.test/directory"},
            {"termsURL","https://ca.example.test/terms"},{"termsAgreed",true},{"apiTrustFile",(root->path()+"/api-root.pem").toStdString()},{"certificateTrustFile",(root->path()+"/leaf-root.pem").toStdString()}};
        original["observerSettings"]={{"host","observer.example.test"},{"port",9443},{"caFile","observer-root.pem"},
            {"registrationId",std::string(32,'a')},{"tokenFile","registration.key"},{"timeoutMs",nullptr}};
        write(original);SettingsDialog dialog(path);dialog.show();QTRY_VERIFY2(save(dialog)->isEnabled(),qPrintable(feedback(dialog)->text()));
        QCOMPARE(dialog.findChild<QComboBox*>("certificateMethod")->currentData().toString(),QString("automatic"));
        port(dialog)->setText("9443");QTest::mouseClick(save(dialog),Qt::LeftButton);
        QTRY_VERIFY(feedback(dialog)->text().startsWith("Saved."));auto expected=original;expected["port"]=9443;QVERIFY(disk()==expected);
    }
    void invalidFieldLeavesStoredBytes() {
        SettingsDialog dialog(path);dialog.show();QTRY_VERIFY2(save(dialog)->isEnabled(),qPrintable(feedback(dialog)->text()));
        port(dialog)->setText("0");QTest::mouseClick(save(dialog),Qt::LeftButton);
        QVERIFY(dialog.findChild<QLabel*>("portFieldError")->isVisible());QVERIFY(disk()==original);QVERIFY(!feedback(dialog)->text().startsWith("Saved."));
    }
    void precommitFailureAndUncertainFeedback() {
        auto io=std::make_shared<DialogIo>();SettingsDialog dialog(path,nullptr,io);dialog.show();QTRY_VERIFY2(save(dialog)->isEnabled(),qPrintable(feedback(dialog)->text()));
        io->write_failure=true;port(dialog)->setText("9443");QTest::mouseClick(save(dialog),Qt::LeftButton);
        QTRY_VERIFY(feedback(dialog)->text()!=QString("Saving…"));QVERIFY(disk()==original);QVERIFY(!feedback(dialog)->text().startsWith("Saved."));
        io->write_failure=false;io->uncertain=true;QTest::mouseClick(save(dialog),Qt::LeftButton);
        QTRY_VERIFY(feedback(dialog)->text()!=QString("Saving…"));QVERIFY(!save(dialog)->isEnabled());QVERIFY(!feedback(dialog)->text().startsWith("Saved."));
        auto expected=original;expected["port"]=9443;QVERIFY(disk()==expected);
        dialog.close();SettingsDialog reopened(path);reopened.show();QTRY_VERIFY(save(reopened)->isEnabled());QCOMPARE(port(reopened)->text(),QString("9443"));
    }
    void closeDuringReadDoesNotBlockGui() {
        auto io=std::make_shared<DialogIo>();io->hold=true;
        auto dialog=new SettingsDialog(path,nullptr,io);dialog->show();QTRY_VERIFY(io->entered.load());
        QElapsedTimer timer;timer.start();delete dialog;QVERIFY(timer.elapsed()<100);io->hold=false;QTRY_VERIFY(io->finished.load());
    }
    void sharedFormDefaultsAndMethodSwitch() {
        EndpointForm form;form.show();QCOMPARE(form.findChild<QLineEdit*>("portField")->text(),QString("443"));
        QCOMPARE(form.findChild<QComboBox*>("certificateMethod")->currentData().toString(),QString("local"));
        form.load(original);auto selector=form.findChild<QComboBox*>("certificateMethod");selector->setCurrentIndex(selector->findData("supplied"));
        QVERIFY(form.findChild<QLineEdit*>("certificateField")->isVisible());selector->setCurrentIndex(selector->findData("local"));
        QVERIFY(!form.findChild<QLineEdit*>("certificateField")->isVisible());QVERIFY(form.draft(root->path().toStdString())==original);
    }
    void actionsStayVisibleAtCurrentScale() {
        SettingsDialog dialog(path);dialog.show();QTRY_VERIFY(save(dialog)->isEnabled());
        auto available=dialog.screen()->availableGeometry();QVERIFY(dialog.width()<=available.width()&&dialog.height()<=available.height());
        auto visible=[&](QPushButton *button){return available.contains(QRect(button->mapToGlobal(QPoint(0,0)),button->size()));};
        auto cancel=dialog.findChild<QPushButton*>("cancelSettings");QVERIFY(visible(save(dialog))&&visible(cancel));
        port(dialog)->setText("9443");QTest::mouseClick(save(dialog),Qt::LeftButton);QTRY_VERIFY(feedback(dialog)->text().startsWith("Saved."));
        QVERIFY(visible(save(dialog))&&visible(cancel));
        auto method=dialog.findChild<QComboBox*>("certificateMethod");method->setCurrentIndex(method->findData("supplied"));QCoreApplication::processEvents();
        auto fields=dialog.findChild<QScrollArea*>("settingsFields");QVERIFY(fields);QCOMPARE(fields->horizontalScrollBar()->maximum(),0);
        auto key=dialog.findChild<QLineEdit*>("privateKeyField");
        QTRY_VERIFY(([&]{fields->ensureWidgetVisible(key);return fields->viewport()->rect().contains(QRect(key->mapTo(fields->viewport(),QPoint(0,0)),key->size()));})());
        QCoreApplication::processEvents();QVERIFY(visible(save(dialog))&&visible(cancel));
        auto image=qEnvironmentVariable("TRAVERSE_TEST_SCALED_SETTINGS_SCREENSHOT");if(!image.isEmpty())QVERIFY(dialog.screen()->grabWindow(0).save(image));
    }
};
QTEST_MAIN(SettingsDialogTests)
#include "settings_dialog_test.moc"
