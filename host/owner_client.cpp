#include "owner_client.hpp"
#include <QJsonDocument>
#include <QJsonParseError>
#include <QProcessEnvironment>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <set>
#include <nlohmann/json.hpp>

namespace traverse {
static qint64 monotonicMs() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return qint64(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}
OwnerClient::OwnerClient(QString runtime_prefix, QString configuration_path, QObject *parent)
    : QObject(parent), prefix(std::move(runtime_prefix)), configuration(std::move(configuration_path)) {
    preparation.setProcessChannelMode(QProcess::SeparateChannels);
    preparation.setStandardErrorFile(QProcess::nullDevice());
    connect(&preparation, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int result, QProcess::ExitStatus status) {
                if (stopping) {
                    if (stopped) stopped(0);
                    return;
                }
                QJsonParseError error{};
                auto document = QJsonDocument::fromJson(preparation.readAllStandardOutput(), &error);
                auto object = document.object();
                if (result || status != QProcess::NormalExit || error.error != QJsonParseError::NoError ||
                    object.value("schemaVersion").toInt() != 1 || !object.value("environment").isObject()) {
                    fail("Cannot prepare the sharing runtime.");
                    return;
                }
                spawn(object.value("environment").toObject());
            });
    connect(&preparation, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) fail("Cannot start the sharing runtime.");
    });
    connect(&poll, &QTimer::timeout, this, [this] { tick(); });
    poll.setInterval(100);
}
OwnerClient::~OwnerClient() {
    publicCAExported = {};
    closeChannel(); // Native EOF/parent guards retain independent cleanup.
    if (child > 1) waitpid(child, nullptr, WNOHANG);
}
void OwnerClient::start() {
    if (started) return;
    started = true;
    preparation.start(prefix + "/bin/traverse", {"--runtime-environment"});
    poll.start();
}
void OwnerClient::spawn(const QJsonObject &profile) {
    auto environment = QProcessEnvironment::systemEnvironment();
    for (auto it = profile.begin(); it != profile.end(); ++it) {
        if (!it.value().isString()) { fail("Invalid sharing runtime environment."); return; }
        environment.insert(it.key(), it.value().toString());
    }
    if (environment.value("TRAVERSE_RUNTIME_PREFIX") != prefix) {
        fail("Sharing runtime identity did not match."); return;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair)) {
        fail("Cannot create the private sharing channel."); return;
    }
    // Environment discovery is fully finished before either endpoint exists.
    // Choose a distinct child target so dup2 always clears CLOEXEC.
    int inherited = pair[1] == 3 ? 4 : 3;
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    bool initialized = result == 0;
    if (!result) result = posix_spawn_file_actions_addclose(&actions, pair[0]);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, pair[1], inherited);
    if (!result) result = posix_spawn_file_actions_addclose(&actions, pair[1]);
    if (!result) result = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (!result) result = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    if (!result) result = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    std::vector<QByteArray> arguments = {(prefix + "/libexec/traverse/traverse-launcher").toUtf8(),
        "--config", configuration.toUtf8(), "--owner-fd", QByteArray::number(inherited),
        "--supervisor-pid", QByteArray::number(getpid())};
    std::vector<char *> argv, envp;
    for (auto &value : arguments) argv.push_back(value.data());
    argv.push_back(nullptr);
    std::vector<QByteArray> entries;
    for (const auto &entry : environment.toStringList()) entries.push_back(entry.toUtf8());
    for (auto &entry : entries) envp.push_back(entry.data());
    envp.push_back(nullptr);
    if (!result) result = posix_spawn(&child, argv[0], &actions, nullptr, argv.data(), envp.data());
    if (initialized) posix_spawn_file_actions_destroy(&actions);
    ::close(pair[1]);
    if (result) { ::close(pair[0]); child = -1; fail("Cannot start the sharing supervisor."); return; }
    descriptor = pair[0];
    readable = std::make_unique<QSocketNotifier>(descriptor, QSocketNotifier::Read, this);
    writable = std::make_unique<QSocketNotifier>(descriptor, QSocketNotifier::Write, this);
    writable->setEnabled(false);
    connect(readable.get(), &QSocketNotifier::activated, this, [this] { receive(); });
    connect(writable.get(), &QSocketNotifier::activated, this, [this] { flush(); });
    if (stopping) stop();
}
void OwnerClient::closeChannel() {
    const bool export_pending = requests.values().contains("export-ca");
    readable.reset(); writable.reset();
    if (descriptor >= 0) ::close(descriptor);
    descriptor = -1;
    incoming.clear(); outgoing.clear(); sent = 0;
    status_pending = false;
    requests.clear();
    if (export_pending && !stopping && publicCAExported) publicCAExported(false,{},{});
}
void OwnerClient::fail(const QString &message) {
    closeChannel();
    if (stateChanged) stateChanged({});
    if (!reported_failure && failed) failed(message);
    reported_failure = true;
}
void OwnerClient::request(const char *action) {
    if (descriptor < 0) return;
    requests.insert(serial + 1,QByteArray(action));
    auto body = QByteArray("{\"schemaVersion\":1,\"requestId\":") + QByteArray::number(++serial) +
                ",\"action\":\"" + action + "\"}";
    quint32 size = quint32(body.size());
    QByteArray frame;
    for (int shift : {24,16,8,0}) frame.append(char((size >> shift) & 255));
    frame += body;
    outgoing.push_back(std::move(frame)); flush();
}
void OwnerClient::flush() {
    while (descriptor >= 0 && !outgoing.empty()) {
        auto &frame = outgoing.front();
        auto count = ::send(descriptor, frame.constData() + sent, size_t(frame.size() - sent), MSG_NOSIGNAL);
        if (count > 0) {
            sent += count;
            if (sent == frame.size()) { outgoing.pop_front(); sent = 0; }
        } else if (count < 0 && errno == EINTR) continue;
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else { fail("The private sharing channel closed."); return; }
    }
    if (writable) writable->setEnabled(!outgoing.empty());
}
void OwnerClient::receive() {
    char data[16384];
    if (descriptor >= 0) {
        ssize_t count;
        do { count=recv(descriptor,data,sizeof(data),0); } while(count<0 && errno==EINTR);
        if (count > 0) incoming.append(data, qsizetype(count));
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        else { closeChannel(); if (stateChanged) stateChanged({}); return; }
    }
    while (incoming.size() >= 4) {
        quint32 size = 0;
        for (int index = 0; index < 4; ++index) size = (size << 8) | quint8(incoming[index]);
        if (!size) { fail("Invalid sharing status."); return; }
        if (quint64(incoming.size()) < quint64(size) + 4) break;
        QJsonParseError error{};
        auto document = QJsonDocument::fromJson(incoming.mid(4, size), &error);
        auto body=incoming.mid(4,size);
        incoming.remove(0, qsizetype(size) + 4);
        if (error.error != QJsonParseError::NoError || !document.isObject()) {
            fail("Invalid sharing status."); return;
        }
        // Qt's JSON object parser keeps the last duplicate key. The versioned
        // owner contract instead rejects ambiguity, including nested state.
        bool duplicate=false;
        std::map<int,std::set<std::string>> keys;
        auto parsed=nlohmann::json::parse(body.begin(),body.end(),
            [&](int depth,nlohmann::json::parse_event_t event,nlohmann::json &part) {
                if(event==nlohmann::json::parse_event_t::object_start)keys[depth+1].clear();
                if(event==nlohmann::json::parse_event_t::key && !keys[depth].insert(part.get<std::string>()).second)duplicate=true;
                return true;
            },false);
        if(duplicate || parsed.is_discarded() || !parsed.is_object() ||
           !parsed.contains("schemaVersion") || !parsed["schemaVersion"].is_number_integer() || parsed["schemaVersion"]!=1) {
            fail("Invalid sharing status."); return;
        }
        if(parsed.contains("publicCA")) {
            const auto &ca=parsed.at("publicCA");
            static const std::set<std::string> fields={"version","domain","pem","fingerprint","validFrom","validUntil"};
            bool valid=ca.is_object()&&ca.size()==fields.size();
            if(valid)for(auto entry=ca.begin();entry!=ca.end();++entry)valid=valid&&fields.count(entry.key());
            valid=valid&&ca.contains("version")&&ca["version"].is_number_integer()&&ca["version"]==1&&
                ca.contains("domain")&&ca["domain"].is_string()&&!ca["domain"].get<std::string>().empty()&&
                ca.contains("pem")&&ca["pem"].is_string()&&ca.contains("fingerprint")&&ca["fingerprint"].is_string()&&
                ca.contains("validFrom")&&ca["validFrom"].is_number_integer()&&ca["validFrom"]>=0&&
                ca.contains("validUntil")&&ca["validUntil"].is_number_integer()&&ca["validUntil"]>ca["validFrom"]&&ca["validUntil"]<=253402300799LL;
            if(valid) {
                auto pem=ca["pem"].get<std::string>(),fingerprint=ca["fingerprint"].get<std::string>();
                valid=pem.rfind("-----BEGIN CERTIFICATE-----",0)==0&&pem.find("PRIVATE KEY")==std::string::npos&&
                    fingerprint.size()==64&&fingerprint.find_first_not_of("0123456789abcdef")==std::string::npos;
            }
            if(!valid) {fail("Invalid public certificate reply.");return;}
        }
        accept(document.object());
        if (descriptor < 0) return;
    }
}
void OwnerClient::accept(const QJsonObject &message) {
    if (message.value("schemaVersion").toDouble() != 1.0) { fail("Unsupported sharing status."); return; }
    QByteArray action;
    if (message.contains("requestId")) {
        auto id=message.value("requestId").toInteger(-1);
        if(id<0 || !requests.contains(quint64(id)) || !message.value("ok").isBool()) {
            fail("Invalid sharing reply."); return;
        }
        action=requests.take(quint64(id));
        if(action=="status")status_pending=false;
    } else if(message.value("event").toString()!="state" || !message.value("state").isObject()) {
        fail("Invalid sharing event."); return;
    }
    if((message.contains("publicCA")&&(action!="export-ca"||!message.value("ok").toBool())) ||
       (action=="export-ca"&&message.value("ok").toBool()&&
        (!message.value("publicCA").isObject()||!message.value("state").isObject()))) {
        if(action=="export-ca"&&publicCAExported)publicCAExported(false,{},{});
        fail("Unsolicited public certificate reply.");return;
    }
    if (message.value("state").isObject()) {
        auto state = message.value("state").toObject();
        auto identity = state.value("instance").toString();
        auto observed = state.value("observedMonotonicMs").toInteger(-1);
        auto now = monotonicMs();
        if (state.value("supervisorPid").toInteger(-1) != child || identity.isEmpty() ||
            (!instance.isEmpty() && identity != instance)) {
            if(action=="export-ca"&&publicCAExported)publicCAExported(false,{},{});
            fail("Sharing status identity did not match."); return;
        }
        instance=identity;
        if(observed<0 || observed>now || now-observed>2000) {
            // A delayed observation is not a command to revoke a valid
            // controller. Hide stale presentation and request fresh state.
            last_state=0;
            if(action=="new-code" && codeRefreshed)codeRefreshed(false);
            if(action=="check-connection" && connectionCheckRequested)connectionCheckRequested(false);
            if(action=="export-ca" && publicCAExported)publicCAExported(false,{},{});
            if(stateChanged)stateChanged({});
            return;
        }
        last_state = observed;
        if(action=="new-code" && codeRefreshed)codeRefreshed(message.value("ok").toBool());
        if(action=="check-connection" && connectionCheckRequested)connectionCheckRequested(message.value("ok").toBool());
        if(action=="export-ca" && publicCAExported)publicCAExported(message.value("ok").toBool(),
            message.value("ok").toBool()?message.value("publicCA").toObject():QJsonObject{},state);
        if (stateChanged) stateChanged(state);
    }
    if (message.contains("ok") && !message.value("state").isObject() && !stopping && !message.value("ok").toBool()) {
        if(action=="new-code" && codeRefreshed)codeRefreshed(false);
        if(action=="check-connection" && connectionCheckRequested)connectionCheckRequested(false);
        if(action=="export-ca" && publicCAExported)publicCAExported(false,{},{});
        if (stateChanged) stateChanged({});
    }
}
void OwnerClient::tick() {
    if (child > 1) {
        int status = 0;
        auto result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            child = -1; closeChannel(); poll.stop();
            if (stateChanged) stateChanged({});
            if (stopped) stopped(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
            return;
        }
        if(result<0 && errno==ECHILD) {
            child=-1;poll.stop();fail("Sharing supervisor ownership was lost.");
            if(stopped)stopped(1);
            return;
        }
    }
    auto now = monotonicMs();
    if (last_state && now - last_state > 2000) { last_state = 0; if (stateChanged) stateChanged({}); }
    if (descriptor >= 0 && !stopping && !status_pending && now - status_sent >= 500) {
        status_pending = true; status_sent = now; request("status");
    }
}
void OwnerClient::newCode() {
    if (!stopping) request("new-code");
}
void OwnerClient::checkConnection() {
    if (!stopping) request("check-connection");
}
void OwnerClient::exportCA() {
    if(!stopping&&descriptor>=0)request("export-ca");
    else if(publicCAExported)publicCAExported(false,{},{});
}
void OwnerClient::stop() {
    stopping = true;
    // EOF, independent of queued replies, starts native input-first teardown.
    closeChannel();
    if (child < 0 && preparation.state() == QProcess::NotRunning) {
        poll.stop(); if (stopped) stopped(0);
    }
}
} // namespace traverse
