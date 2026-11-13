#include "connection_feedback.hpp"
#include <QJsonArray>
#include <optional>

namespace traverse {
namespace {
std::optional<qint64> integer(const QJsonValue &value) {
    if(!value.isDouble())return {};
    auto number=value.toInteger(-1);
    if(number<0 || value.toDouble()!=double(number))return {};
    return number;
}
QString observer_name(const QJsonObject &check) {
    auto endpoint=check.value("observer").toObject();auto host=endpoint.value("host").toString();
    auto port=integer(endpoint.value("port"));
    if(host.isEmpty() || !port || *port<1 || *port>65535)return {};
    if(host.contains(':'))host="["+host+"]";
    return host+(*port==443?QString{}:":"+QString::number(*port));
}
QString failure_reason(const QString &reason) {
    if(reason=="dnsFailed" || reason=="dnsMismatch")return "DNS check failed";
    if(reason=="tlsFailed")return "TLS check failed";
    if(reason=="connectionFailed")return "Connection check failed";
    if(reason=="timeout")return "Connection check timed out";
    if(reason=="unauthorized")return "Observer authentication failed";
    return "Connection verification failed";
}
struct PathResult {int total=0,verified=0,failed=0;};
bool definitive_failure(const QString &status) {
    return status=="dnsFailed" || status=="dnsMismatch" || status=="connectionFailed" ||
        status=="tlsFailed" || status=="httpRejected" || status=="invalidReceipt" ||
        status=="unauthorized" || status=="internalFailure" || status=="agentFailed" ||
        status=="mediaFailed" || status=="endpointChanged" || status=="cleanupFailed" ||
        status=="receiptMismatch";
}
QString path_status(const PathResult &path) {
    if(path.total && path.verified==path.total)return "verified";
    if(path.verified)return "partly verified";
    return path.failed?"failed":"unavailable";
}
QString startup_failure(const QString &stage) {
    if(stage=="adapter")return "The desktop could not become ready.";
    if(stage=="turn")return "The relay could not start.";
    if(stage=="service")return "The connection service could not start.";
    if(stage=="frontend")return "The HTTPS listener could not start.";
    return "Sharing could not start.";
}
}
ConnectionFeedback connection_feedback(const QJsonObject &state,qint64 now) {
    ConnectionFeedback result{"URL: Status unavailable","Media: Verification unavailable",{},{},false};
    if(state.isEmpty())return result;
    auto check=state.value("urlCheck").toObject();auto status=check.value("status").toString();
    auto reason=check.value("reason").toString();auto observer=observer_name(check);
    auto scope=observer.isEmpty()?QString{}:" from "+observer;
    auto local=state.value("localHttps").toObject().value("status").toString();
    if(status=="verified")result.url="URL: HTTPS verified"+scope;
    else if(status=="partial") {
        result.url="URL: HTTPS partly verified"+scope;
        for(const auto &entry:check.value("addresses").toArray()) {
            auto value=entry.toObject().value("status").toString();
            if(definitive_failure(value))
                result.notification_body="HTTPS partly verified"+scope+". Some URL checks failed.";
        }
    }
    else if(status=="checking" || status=="cleaning" || status=="cancelling")
        result.url="URL: Checking"+scope+QString::fromUtf8("…");
    else if(status=="cancelled" || reason=="controllerPriority")
        result.url="URL: Check cancelled for the active session";
    else if(status=="failed") {
        result.notification_body=failure_reason(reason)+scope+".";
        result.url="URL: "+failure_reason(reason)+scope;
    } else if(local=="passed")result.url="URL: Local HTTPS verified. Observer unavailable";
    else if(local=="pending")result.url=QString::fromUtf8("URL: Checking…");

    auto peer=state.value("peer").toObject();
    bool connected=peer.value("peerActive").toBool() && peer.value("controlOpen").toBool() &&
        peer.value("rtcState").toString()=="connected";
    if(connected) {
        auto health=peer.value("health").toObject();auto observed=health.value("lastObservation").toObject();
        auto generation=integer(peer.value("generation")),health_generation=integer(health.value("generation"));
        auto stamp=integer(observed.value("observedMonotonicMs")),owner_stamp=integer(state.value("observedMonotonicMs"));
        bool valid=generation && *generation>0 && generation==health_generation && stamp && owner_stamp &&
            *stamp<=*owner_stamp && *owner_stamp<=now;
        for(auto field:{"decodedFrames","presentedFrames","width","height"}) {
            auto count=integer(observed.value(field));valid=valid && count && *count>0;
        }
        if(valid) {
            result.media="Media: Last video verified "+QString::number((now-*stamp)/1000)+" s ago";
            if(health.value("status").toString()!="observed")result.media+=". Verification unavailable";
        } else result.media=health.value("status").toString()=="waiting"?
            "Media: Waiting for video verification":"Media: Verification unavailable";
    } else {
        auto media=check.value("media").toString();
        if(media=="checking" || media=="cleanupPending")result.media="Media: Checking"+scope+QString::fromUtf8("…");
        else if(media=="activeSession")result.media="Media: Waiting for Chrome to reconnect";
        else if(media=="verified" || media=="partial" || media=="failed") {
            PathResult direct,relay;
            for(const auto &entry:check.value("mediaChecks").toObject().value("addresses").toArray()) {
                auto row=entry.toObject();auto mode=row.value("mode").toString();
                if(mode!="direct" && mode!="relay")continue;
                auto &path=mode=="direct"?direct:relay;++path.total;
                auto value=row.value("status").toString();
                if(value=="verified")++path.verified;
                else if(definitive_failure(value))++path.failed;
            }
            result.media="Media: Direct "+path_status(direct)+"; relay "+path_status(relay)+scope;
            if(result.notification_body.isEmpty() && (direct.failed || relay.failed))
                result.notification_body="Video check failed"+scope+". Direct "+path_status(direct)+"; relay "+path_status(relay)+".";
        }
    }
    bool active_session=connected || state.value("authority").toObject().value("paired").toBool() ||
        check.value("media").toString()=="activeSession" || reason=="controllerPriority";
    if(active_session) {
        result.notification_body.clear();
        if(status=="failed")result.url="URL: Last check failed"+scope;
    }
    if(!result.notification_body.isEmpty()) {
        auto started=integer(check.value("startedMonotonicMs"));auto identity=state.value("instance").toString();
        if(started && !identity.isEmpty())result.notification_key=identity+":"+QString::number(*started);
        else result.notification_body.clear();
    }
    if(state.value("phase").toString()=="failed") {
        result.startup_failure=true;
        result.notification_body=startup_failure(state.value("stage").toString());
        result.url="URL: "+result.notification_body;
    }
    return result;
}
}
