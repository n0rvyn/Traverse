// Test-only UI driver: actual widgets/native supervisor, never installed.
#include "sharing_window.hpp"
#include <QApplication>
#include <QClipboard>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QScreen>
#include <QSocketNotifier>
#include <QTest>
#include <QTimer>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

static void report(const QJsonObject &value) {
    auto bytes=QJsonDocument(value).toJson(QJsonDocument::Compact);
    std::fwrite(bytes.constData(),1,size_t(bytes.size()),stdout);
    std::fputc('\n',stdout);std::fflush(stdout);
}
int main(int argc,char **argv) {
    if(geteuid()==0)return 2;
    QApplication app(argc,argv);
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
    traverse::SharingWindow window(qEnvironmentVariable("TRAVERSE_TEST_HOST_PREFIX"),
        qEnvironmentVariable("TRAVERSE_TEST_HOST_CONFIG"));
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
                    {"urlCheck",window.findChild<QLabel*>("urlCheck")->text()}});
            } else if(action=="click") {
                auto name=message.value("control").toString();
                bool allowed=name=="copyCode"||name=="copyUrl"||name=="newCode"||name=="stopSharing";
                auto button=allowed?window.findChild<QPushButton*>(name):nullptr;
                bool clicked=button&&button->isEnabled();
                if(clicked) {
                    if(name!="stopSharing")window.findChild<QScrollArea*>("sharingDetails")->ensureWidgetVisible(button);
                    QTest::mouseClick(button,Qt::LeftButton);
                }
                report({{"clicked",clicked}});
            } else if(action=="snapshot") {
                bool safe=!window.findChild<QPushButton*>("copyCode")->isEnabled()&&window.findChild<QLabel*>("pairingCode")->text()=="Used";
                bool saved=safe&&window.grab().save(qEnvironmentVariable("TRAVERSE_TEST_HOST_IMAGE"));
                report({{"saved",saved}});
            } else if(action=="close") {
                report({{"closing",true}});window.close();
            } else report({{"unknownAction",true}});
        }
    });
    report({{"fixtureReady",true}});
    return app.exec();
}
