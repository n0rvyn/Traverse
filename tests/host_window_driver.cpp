// Test-only UI driver: actual widgets/native supervisor, never installed.
#include "sharing_window.hpp"
#include "settings_dialog.hpp"
#include <QAccessible>
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QPalette>
#include <QPushButton>
#include <QLineEdit>
#include <QScrollArea>
#include <QScreen>
#include <QSocketNotifier>
#include <QTest>
#include <QTimer>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <condition_variable>
#include <chrono>
#include <mutex>

struct ExportFixtureIo : traverse::PublicCertificateIo {
    mutable std::atomic<bool> entered{false};
    mutable std::mutex mutex;
    mutable std::condition_variable wake;
    mutable bool released=false;
    void write(const QJsonObject &certificate,const QJsonObject &state,const QString &destination,
        const std::shared_ptr<std::atomic<bool>> &cancelled) const override {
        entered.store(true);
        std::unique_lock<std::mutex> lock(mutex);
        while(!released&&!cancelled->load())wake.wait_for(lock,std::chrono::milliseconds(20));
        lock.unlock();
        traverse::PublicCertificateIo::write(certificate,state,destination,cancelled);
    }
};

static void report(const QJsonObject &value) {
    auto bytes=QJsonDocument(value).toJson(QJsonDocument::Compact);
    std::fwrite(bytes.constData(),1,size_t(bytes.size()),stdout);
    std::fputc('\n',stdout);std::fflush(stdout);
}
static QJsonObject focus_report() {
    auto widget=QApplication::focusWidget();
    auto button=qobject_cast<QPushButton*>(widget);
    auto accessible=button?QAccessible::queryAccessibleInterface(button):nullptr;
    // Do not export selectable URL/code label values through diagnostics.
    return {{"focusControl",widget?widget->objectName():QString{}},
        {"focusClass",widget?QString(widget->metaObject()->className()):QString{}},
        {"accessibleName",accessible?accessible->text(QAccessible::Name):QString{}},
        {"accessibleButton",accessible&&accessible->role()==QAccessible::Button},
        {"focused",widget&&widget->hasFocus()},
        {"windowActive",widget&&widget->window()->isActiveWindow()}};
}
int main(int argc,char **argv) {
    if(geteuid()==0)return 2;
    QApplication app(argc,argv);
    // Synthetic palette coverage only; this does not certify a desktop theme.
    if(qEnvironmentVariable("TRAVERSE_TEST_DARK_PALETTE")=="1") {
        app.setStyle("Fusion");
        auto palette=app.palette();
        palette.setColor(QPalette::Window,QColor(40,40,40));
        palette.setColor(QPalette::WindowText,QColor(235,235,235));
        palette.setColor(QPalette::Base,QColor(30,30,30));
        palette.setColor(QPalette::Text,QColor(235,235,235));
        palette.setColor(QPalette::Button,QColor(55,55,55));
        palette.setColor(QPalette::ButtonText,QColor(235,235,235));
        palette.setColor(QPalette::Disabled,QPalette::WindowText,QColor(130,130,130));
        palette.setColor(QPalette::Disabled,QPalette::Text,QColor(130,130,130));
        palette.setColor(QPalette::Disabled,QPalette::ButtonText,QColor(130,130,130));
        app.setPalette(palette);
    }
    if(argc==2 && QByteArray(argv[1])=="--clipboard-probe") {
        QByteArray input;
        for(int value;(value=std::getchar())!='\n' && value!=EOF;)input.append(char(value));
        auto expected=QJsonDocument::fromJson(input).object().value("expected").toString();
        QTimer::singleShot(0,&app,[&]{
            bool matches=false;
            for(int attempt=0;attempt<100 && !matches;attempt++) {
                matches=QApplication::clipboard()->text()==expected;
                if(!matches)QTest::qWait(10);
            }
            report({{"matches",matches}});app.quit();
        });
        return app.exec();
    }
    auto blocked=qEnvironmentVariable("TRAVERSE_TEST_BLOCK_EXPORT")=="1"?std::make_shared<ExportFixtureIo>():nullptr;
    traverse::SharingWindow window(qEnvironmentVariable("TRAVERSE_TEST_HOST_PREFIX"),
        qEnvironmentVariable("TRAVERSE_TEST_HOST_CONFIG"),blocked?blocked:std::make_shared<traverse::PublicCertificateIo>());
    window.show();
    QTimer::singleShot(0,&window,[&]{window.start();});
    fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL)|O_NONBLOCK);
    QSocketNotifier commands(STDIN_FILENO,QSocketNotifier::Read,&app);
    QByteArray input;
    QObject::connect(&commands,&QSocketNotifier::activated,&app,[&]{
        char bytes[4096];ssize_t count;
        while((count=read(STDIN_FILENO,bytes,sizeof(bytes)))>0)input.append(bytes,int(count));
        if(!count) {commands.setEnabled(false);window.close();return;}
        while(input.contains('\n')) {
            auto end=input.indexOf('\n');auto message=QJsonDocument::fromJson(input.left(end)).object();input.remove(0,end+1);
            auto action=message.value("action").toString();
            if(action=="view") {
                auto stop=window.findChild<QPushButton*>("stopSharing");
                auto code=window.findChild<QPushButton*>("copyCode");
                auto remote=window.findChild<QPushButton*>("copyUrl");
                auto fresh=window.findChild<QPushButton*>("newCode");
                auto label=window.findChild<QLabel*>("pairingCode");
                // No code or token value enters this fixed fixture report.
                report({{"status",window.findChild<QLabel*>("connectionStatus")->text()},
                    {"codeAvailable",code->isEnabled()},{"codeUsed",label->text()=="Used"},
                    {"codeExpired",label->text()=="Expired"},
                    {"urlCopyAvailable",remote->isEnabled()},{"newCodeAvailable",fresh->isEnabled()},
                    {"stopInsideWindow",window.rect().contains(QRect(stop->mapTo(&window,QPoint(0,0)),stop->size()))},
                    {"stopOnScreen",window.screen()->availableGeometry().contains(QRect(stop->mapToGlobal(QPoint(0,0)),stop->size()))},
                    {"urlCheck",window.findChild<QLabel*>("urlCheck")->text()},
                    {"mediaCheck",window.findChild<QLabel*>("mediaCheck")->text()}});
            } else if(action=="focus") {
                report(focus_report());
            } else if(action=="click") {
                auto name=message.value("control").toString();
                bool allowed=name=="copyCode"||name=="copyUrl"||name=="newCode"||name=="stopSharing"||name=="settingsButton"||name=="exportPublicCA";
                auto button=allowed?window.findChild<QPushButton*>(name):nullptr;
                bool clicked=button&&button->isEnabled();
                if(clicked) {
                    if(name!="stopSharing"&&name!="settingsButton")window.findChild<QScrollArea*>("sharingDetails")->ensureWidgetVisible(button);
                    QTest::mouseClick(button,Qt::LeftButton);
                }
                report({{"clicked",clicked}});
            } else if(action=="exportView") {
                auto button=window.findChild<QPushButton*>("exportPublicCA");
                auto picker=window.findChild<QFileDialog*>("publicCertificatePicker");
                auto feedback=window.findChild<QLabel*>("publicCAFeedback");
                report({{"visible",button->isVisible()},{"enabled",button->isEnabled()},
                    {"pickerVisible",picker&&picker->isVisible()},{"feedback",feedback->text()},
                    {"writeEntered",blocked&&blocked->entered.load()}});
            } else if(action=="exportSelect") {
                auto picker=window.findChild<QFileDialog*>("publicCertificatePicker");
                bool selected=picker&&picker->isVisible();
                if(selected) {
                    picker->selectFile(message.value("path").toString());
                    // Queue acceptance: the standard overwrite confirmation has
                    // its own nested event loop, which must stay driveable.
                    QTimer::singleShot(0,picker,[picker]{QMetaObject::invokeMethod(picker,"accept",Qt::DirectConnection);});
                }
                report({{"selected",selected}});
            } else if(action=="exportCancel") {
                auto picker=window.findChild<QFileDialog*>("publicCertificatePicker");
                if(picker)picker->reject();
                report({{"cancelled",picker!=nullptr}});
            } else if(action=="overwrite") {
                QMessageBox *confirmation=nullptr;
                for(auto widget:QApplication::topLevelWidgets()) {
                    auto box=qobject_cast<QMessageBox*>(widget);if(box&&box->isVisible())confirmation=box;
                }
                if(confirmation) {
                    auto button=confirmation->button(message.value("accept").toBool()?QMessageBox::Yes:QMessageBox::No);
                    if(button)QTest::mouseClick(button,Qt::LeftButton);
                }
                report({{"confirmationVisible",confirmation!=nullptr}});
            } else if(action=="releaseExport") {
                if(blocked) {std::lock_guard<std::mutex> lock(blocked->mutex);blocked->released=true;blocked->wake.notify_all();}
                report({{"released",blocked!=nullptr}});
            } else if(action=="resetExport") {
                if(blocked) {std::lock_guard<std::mutex> lock(blocked->mutex);blocked->released=false;blocked->entered.store(false);}
                report({{"reset",blocked!=nullptr}});
            } else if(action=="settingsView") {
                auto dialog=window.findChild<QDialog*>("settingsDialog");
                auto save=dialog?dialog->findChild<QPushButton*>("saveSettings"):nullptr;
                auto field=dialog?dialog->findChild<QLineEdit*>("portField"):nullptr;
                auto feedback=dialog?dialog->findChild<QLabel*>("saveFeedback"):nullptr;
                report({{"visible",dialog&&dialog->isVisible()},{"saveEnabled",save&&save->isEnabled()},
                    {"port",field?field->text():QString{}},{"feedback",feedback?feedback->text():QString{}}});
            } else if(action=="settingsSave") {
                auto dialog=window.findChild<QDialog*>("settingsDialog");
                auto save=dialog?dialog->findChild<QPushButton*>("saveSettings"):nullptr;
                bool accepted=save&&save->isEnabled();
                if(accepted) {
                    dialog->findChild<QLineEdit*>("portField")->setText(message.value("port").toString());
                    QTest::mouseClick(save,Qt::LeftButton);
                }
                report({{"accepted",accepted}});
            } else if(action=="settingsClose") {
                auto dialog=window.findChild<QDialog*>("settingsDialog");
                if(dialog)dialog->close();
                report({{"closed",dialog!=nullptr}});
            } else if(action=="snapshot"||action=="snapshotError") {
                bool safe=!window.findChild<QPushButton*>("copyCode")->isEnabled()&&window.findChild<QLabel*>("pairingCode")->text()=="Used";
                auto path=qEnvironmentVariable("TRAVERSE_TEST_HOST_IMAGE");if(action=="snapshotError")path+=".error.png";
                bool saved=safe&&window.grab().save(path);
                report({{"saved",saved}});
            } else if(action=="close") {
                report({{"closing",true}});window.close();
            } else report({{"unknownAction",true}});
        }
    });
    report({{"fixtureReady",true}});
    return app.exec();
}
