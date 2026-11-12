#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <atomic>
#include <memory>
namespace traverse {
QByteArray checkedPublicCertificate(const QJsonObject &certificate,const QJsonObject &owned_state);
void exportPublicCertificate(const QJsonObject &certificate,const QJsonObject &owned_state,const QString &destination,
    const std::shared_ptr<std::atomic<bool>> &cancelled);
// Injectable I/O boundary for pending-write lifecycle tests; no runtime flags.
struct PublicCertificateIo {
    virtual ~PublicCertificateIo()=default;
    virtual void write(const QJsonObject &certificate,const QJsonObject &owned_state,const QString &destination,
        const std::shared_ptr<std::atomic<bool>> &cancelled) const;
};
}
