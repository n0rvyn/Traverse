#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QHash>
#include <QObject>
#include <QProcess>
#include <QSocketNotifier>
#include <QTimer>
#include <deque>
#include <functional>
#include <memory>
#include <sys/types.h>

namespace traverse {
// UI endpoint only: no media headers, private runtime linkage or owner logs.
class OwnerClient : public QObject {
    QString prefix, configuration, instance;
    QProcess preparation;
    QTimer poll;
    std::unique_ptr<QSocketNotifier> readable, writable;
    int descriptor = -1;
    pid_t child = -1;
    bool stopping = false, started = false, status_pending = false, reported_failure = false;
    quint64 serial = 0;
    qint64 last_state = 0, status_sent = 0;
    QByteArray incoming;
    std::deque<QByteArray> outgoing;
    QHash<quint64,QByteArray> requests;
    qsizetype sent = 0;
    void spawn(const QJsonObject &environment);
    void receive();
    void flush();
    void request(const char *action);
    void tick();
    void accept(const QJsonObject &message);
    void fail(const QString &message);
    void closeChannel();

  public:
    OwnerClient(QString runtime_prefix, QString configuration_path, QObject *parent = nullptr);
    ~OwnerClient() override;
    std::function<void(const QJsonObject &)> stateChanged;
    std::function<void(const QString &)> failed;
    std::function<void(int)> stopped;
    std::function<void(bool)> codeRefreshed;
    void start();
    void stop();
    void newCode();
};
} // namespace traverse
