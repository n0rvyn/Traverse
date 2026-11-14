#include "sharing_window.hpp"
#include <QApplication>
#include <QDBusConnection>
#include <QDBusContext>
#include <QDBusMessage>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QJsonArray>
#include <QTest>
#include <QVariantMap>
#include <chrono>

struct Notice {QString app,summary,body;QStringList actions;int expiration;};
class NotificationReceiver:public QObject,protected QDBusContext {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface","org.freedesktop.Notifications")
  public:
    QList<Notice> notices;
    bool hold_reply=false;
  public slots:
    uint Notify(const QString &app,uint,const QString &,const QString &summary,const QString &body,
                const QStringList &actions,const QVariantMap &,int expiration) {
        notices.append({app,summary,body,actions,expiration});
        if(hold_reply)setDelayedReply(true);
        return uint(notices.size());
    }
};
namespace traverse {
class SharingFeedbackTests:public QObject {
    Q_OBJECT
    NotificationReceiver receiver;
    QDBusConnection receiver_bus=QDBusConnection::connectToBus(QDBusConnection::SessionBus,"notification-fixture");
    static qint64 now() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    static QJsonObject state() {
        auto stamp=now();
        return {{"instance","feedback-fixture"},{"phase","ready"},{"stage","sharing"},{"observedMonotonicMs",stamp},
            {"localHttps",QJsonObject{{"status","passed"}}},
            {"authority",QJsonObject{{"armed",true},{"paired",false},{"codeStatus","available"},
                {"code","test-code"},{"expiresMonotonicMs",stamp+300000}}},
            {"urlCheck",QJsonObject{{"schemaVersion",1},{"status","verified"},{"reason",""},
                {"startedMonotonicMs",stamp-1000},{"externalReachability","unknown"},
                {"observer",QJsonObject{{"host","observer.example.test"},{"port",9443}}},
                {"media","verified"},{"mediaChecks",QJsonObject{{"status","verified"},{"addresses",QJsonArray{
                    QJsonObject{{"address","127.0.0.1"},{"mode","relay"},{"status","verified"}},
                    QJsonObject{{"address","127.0.0.1"},{"mode","direct"},{"status","verified"}}}}}}}}};
    }
    static void active(QJsonObject &value,qint64 observed) {
        value["authority"]=QJsonObject{{"armed",true},{"paired",true},{"codeStatus","used"}};
        value["peer"]=QJsonObject{{"generation",7},{"peerActive",true},{"controlOpen",true},{"rtcState","connected"},
            {"health",QJsonObject{{"schemaVersion",1},{"generation",7},{"status","observed"},
                {"lastObservation",QJsonObject{{"observedMonotonicMs",observed},{"decodedFrames",33},
                    {"presentedFrames",34},{"width",640},{"height",480}}}}}};
    }
  private slots:
    void initTestCase() {
        QApplication::setQuitOnLastWindowClosed(false);
        auto bus=QDBusConnection::sessionBus();QVERIFY(bus.isConnected());
        QVERIFY(receiver_bus.isConnected());
        QVERIFY(receiver_bus.registerService("org.freedesktop.Notifications"));
        QVERIFY(receiver_bus.registerObject("/org/freedesktop/Notifications",&receiver,QDBusConnection::ExportAllSlots));
        auto call=QDBusMessage::createMethodCall("org.freedesktop.Notifications","/org/freedesktop/Notifications",
            "org.freedesktop.Notifications","Notify");
        call.setArguments({QString("Fixture"),uint(0),QString(),QString("Positive control"),QString(),
            QStringList{},QVariantMap{},-1});
        bus.asyncCall(call);QTRY_COMPARE(receiver.notices.size(),1);receiver.notices.clear();
    }
    void init(){receiver.notices.clear();receiver.hold_reply=false;}
    void certificateHintFollowsActiveOwner() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();
        value["configuredUrl"]="https://apex.norvyn.com/remote/";
        value["issuer"]=QJsonObject{{"localAuthority",QJsonObject{{"available",true}}}};
        window.updateState(value);
        QCOMPARE(window.trust_instruction->text(),QString("Trust this CA once on each Chrome client."));
        QVERIFY(window.export_ca->isEnabled());
        value["publicTlsSource"]="proxy";window.updateState(value);
        QCOMPARE(window.trust_instruction->text(),QString::fromUtf8("This URL uses your proxy’s certificate."));
        QVERIFY(window.export_ca->isEnabled());
        window.updateState({});
        QCOMPARE(window.trust_instruction->text(),QString::fromUtf8("This URL uses your proxy’s certificate."));
        window.updateState(value);
        auto screenshot=qEnvironmentVariable("TRAVERSE_TEST_PROXY_HINT_SCREENSHOT");
        if(!screenshot.isEmpty()) {window.show();QApplication::processEvents();QVERIFY(window.grab().save(screenshot));}
        value["publicTlsSource"]="host";window.updateState(value);
        QCOMPARE(window.trust_instruction->text(),QString("Trust this CA once on each Chrome client."));
    }
    void checkerAndIdleMedia() {
        SharingWindow window("/unused","/unused/config.json");window.updateState(state());
        QVERIFY(window.url_check->text().contains("observer.example.test:9443"));
        QVERIFY(window.url_check->text().contains("HTTPS verified"));
        QVERIFY(window.media_check->text().contains("Direct verified"));
        QVERIFY(window.media_check->text().contains("relay verified"));
        QCOMPARE(receiver.notices.size(),0);
    }
    void actualObservationAgeAndGeneration() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();active(value,now()-2300);
        window.updateState(value);QVERIFY(window.media_check->text().contains("Last video verified 2 s ago"));
        QTest::qWait(1100);value["observedMonotonicMs"]=now();window.updateState(value);
        QVERIFY(!window.media_check->text().contains("2 s ago"));
        QVERIFY(window.media_check->text().contains("Last video verified"));
        auto peer=value["peer"].toObject();auto health=peer["health"].toObject();health["generation"]=8;
        peer["health"]=health;value["peer"]=peer;window.updateState(value);
        QVERIFY(!window.media_check->text().contains("Last video verified"));
        health["generation"]=7;auto observation=health["lastObservation"].toObject();
        observation["observedMonotonicMs"]=now()+10000;health["lastObservation"]=observation;
        peer["health"]=health;value["peer"]=peer;window.updateState(value);
        QVERIFY(!window.media_check->text().contains("Last video verified"));
        QCOMPARE(receiver.notices.size(),0);
    }
    void oneNativeNoticePerFailedCheck() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["status"]="failed";check["reason"]="connectionFailed";value["urlCheck"]=check;
        window.updateState(value);QTRY_COMPARE(receiver.notices.size(),1);
        for(int i=0;i<5;++i)window.updateState(value);
        check["startedMonotonicMs"]=check["startedMonotonicMs"].toInteger()+1;check["reason"]="dnsFailed";
        value["urlCheck"]=check;window.updateState(value);
        QTRY_VERIFY(receiver.notices.size()>=2);QTRY_VERIFY(receiver.notices.last().body.contains("DNS"));
        QCOMPARE(receiver.notices.size(),2);
        for(const auto &notice:receiver.notices) {
            QCOMPARE(notice.app,QString("Traverse"));QVERIFY(notice.actions.isEmpty());QCOMPARE(notice.expiration,-1);
            QVERIFY(notice.body.contains("observer.example.test:9443"));
            QVERIFY(!notice.body.contains("test-code"));QVERIFY(!notice.body.contains("registrationId"));
            QVERIFY(!notice.body.contains("PRIVATE KEY"));
        }
    }
    void cancellationAndUnavailableAreNotUnreachable() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["status"]="cancelled";check["reason"]="controllerPriority";check["media"]="activeSession";
        value["urlCheck"]=check;window.updateState(value);QVERIFY(window.url_check->text().contains("cancelled"));
        check["status"]="unavailable";check["reason"]="";check["media"]="unavailable";
        check.remove("mediaChecks");value["urlCheck"]=check;window.updateState(value);
        QVERIFY(window.media_check->text().contains("unavailable",Qt::CaseInsensitive));
        QCOMPARE(receiver.notices.size(),0);
    }
    void mediaFailureAfterHttpsSuccessNotifiesItsPath() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["media"]="partial";check["mediaChecks"]=QJsonObject{{"status","partial"},{"addresses",QJsonArray{
            QJsonObject{{"address","127.0.0.1"},{"mode","direct"},{"status","mediaFailed"}},
            QJsonObject{{"address","127.0.0.1"},{"mode","relay"},{"status","verified"}}}}};
        value["urlCheck"]=check;window.updateState(value);QTRY_COMPARE(receiver.notices.size(),1);
        QVERIFY(window.media_check->text().contains("Direct failed"));
        QVERIFY(window.media_check->text().contains("relay verified"));
        QVERIFY(!receiver.notices[0].body.contains("unreachable"));
    }
    void activeControllerSuppressesOldCheckFailure() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();active(value,now()-2300);
        auto check=value["urlCheck"].toObject();check["status"]="failed";check["reason"]="connectionFailed";
        check["media"]="activeSession";value["urlCheck"]=check;window.updateState(value);
        QVERIFY(window.url_check->text().contains("Last check failed"));
        QVERIFY(window.media_check->text().contains("Last video verified"));
        QCOMPARE(receiver.notices.size(),0);
    }
    void mediaDnsFailureIsNotMissingEvidence() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["media"]="failed";check["mediaChecks"]=QJsonObject{{"status","failed"},{"addresses",QJsonArray{
            QJsonObject{{"address","127.0.0.1"},{"mode","direct"},{"status","dnsMismatch"}},
            QJsonObject{{"address","127.0.0.1"},{"mode","relay"},{"status","receiptMismatch"}}}}};
        value["urlCheck"]=check;window.updateState(value);QTRY_COMPARE(receiver.notices.size(),1);
        QVERIFY(window.media_check->text().contains("Direct failed; relay failed"));
        QVERIFY(!receiver.notices[0].body.contains("unavailable"));
    }
    void partialUrlFailurePreservesTheWorkingPaths() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["status"]="partial";check["media"]="unavailable";check.remove("mediaChecks");
        check["addresses"]=QJsonArray{QJsonObject{{"address","127.0.0.1"},{"status","verified"}},
            QJsonObject{{"address","127.0.0.2"},{"status","connectionFailed"}}};
        value["urlCheck"]=check;window.updateState(value);QTRY_COMPARE(receiver.notices.size(),1);
        QVERIFY(window.url_check->text().contains("partly verified"));
        QVERIFY(!receiver.notices[0].body.contains("unreachable"));
    }
    void startupFailureIsNotRepeated() {
        SharingWindow window("/unused","/unused/config.json");auto value=state();value["phase"]="failed";value["stage"]="frontend";
        window.updateState(value);window.updateState(value);
        window.client.failed("Cannot start the sharing runtime.");
        QTRY_COMPARE(receiver.notices.size(),1);
        QVERIFY(window.stop_button->isEnabled());
    }
    void unavailableNotificationServiceKeepsInlineFailure() {
        QVERIFY(receiver_bus.unregisterService("org.freedesktop.Notifications"));
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["status"]="failed";check["reason"]="connectionFailed";value["urlCheck"]=check;
        window.updateState(value);QVERIFY(window.url_check->text().contains("Connection check failed"));
        QVERIFY(window.stop_button->isEnabled());
        QTRY_VERIFY(window.findChildren<QDBusPendingCallWatcher*>().isEmpty());
        QVERIFY(receiver_bus.registerService("org.freedesktop.Notifications"));
        check["startedMonotonicMs"]=check["startedMonotonicMs"].toInteger()+1;value["urlCheck"]=check;
        window.updateState(value);QTRY_COMPARE(receiver.notices.size(),1);
    }
    void pendingNotificationDoesNotBlockTheUi() {
        receiver.hold_reply=true;
        SharingWindow window("/unused","/unused/config.json");auto value=state();auto check=value["urlCheck"].toObject();
        check["status"]="failed";check["reason"]="connectionFailed";value["urlCheck"]=check;
        window.updateState(value);QTRY_COMPARE(receiver.notices.size(),1);
        QVERIFY(!window.findChildren<QDBusPendingCallWatcher*>().isEmpty());
        bool progressed=false;QTimer::singleShot(0,&window,[&]{progressed=true;});QTRY_VERIFY(progressed);
        QVERIFY(window.stop_button->isEnabled());
    }
};
}
QTEST_MAIN(traverse::SharingFeedbackTests)
#include "sharing_feedback_test.moc"
