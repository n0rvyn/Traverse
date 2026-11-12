#include "public_certificate.hpp"
#include "local_authority.hpp"
#include "endpoint_settings.hpp"
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>
#include <QUrl>
#include <stdexcept>
namespace traverse {
namespace {
[[noreturn]] void unavailable(){throw std::runtime_error("Public certificate is unavailable. Try again when sharing is ready.");}
}
QByteArray checkedPublicCertificate(const QJsonObject &certificate,const QJsonObject &owned_state) {
    const auto current=owned_state.value("issuer").toObject().value("localAuthority").toObject();
    auto url=QUrl(owned_state.value("configuredUrl").toString());
    if(owned_state.value("localHttps").toObject().value("status").toString()!="passed"||
       !current.value("available").toBool()||!url.isValid()||url.scheme()!="https"||url.host().isEmpty())unavailable();
    auto encoded=QJsonDocument(certificate).toJson(QJsonDocument::Compact);
    auto value=nlohmann::json::parse(encoded.begin(),encoded.end());
    if(!value.is_object()||value.size()!=6||!value.contains("version")||value.at("version")!=1||
       !value.contains("domain")||!value.at("domain").is_string()||!value.contains("pem")||!value.at("pem").is_string())unavailable();
    for(auto key:{"fingerprint","validFrom","validUntil"})if(!certificate.contains(key)||!current.contains(key)||certificate.value(key)!=current.value(key))unavailable();
    auto url_host=url.host().toStdString();
    if(url_host.find(':')==std::string::npos)url_host=QUrl::toAce(url.host()).toStdString();
    auto host=EndpointSettings::normalize_host(url_host);
    if(EndpointSettings::normalize_host(value.at("domain").get<std::string>())!=host||
       EndpointSettings::normalize_host(current.value("domain").toString().toStdString())!=host)unavailable();
    nlohmann::json metadata={{"fingerprint",value.at("fingerprint")},{"validFrom",value.at("validFrom")},{"validUntil",value.at("validUntil")}};
    auto checked=checked_local_authority(value.at("pem").get<std::string>(),metadata,host);
    return QByteArray::fromStdString(checked.at("pem").get<std::string>());
}
void exportPublicCertificate(const QJsonObject &certificate,const QJsonObject &owned_state,const QString &destination,const std::shared_ptr<std::atomic<bool>> &cancelled) {
    if(!cancelled||cancelled->load())throw std::runtime_error("Certificate export cancelled.");
    const auto pem=checkedPublicCertificate(certificate,owned_state);
    if(cancelled->load())throw std::runtime_error("Certificate export cancelled.");
    QSaveFile file(destination);file.setDirectWriteFallback(false);
    if(!file.open(QIODevice::WriteOnly))throw std::runtime_error("Cannot write the certificate. Choose another location.");
    if(file.write(pem)!=pem.size()||cancelled->load()) {
        file.cancelWriting();throw std::runtime_error("Certificate export did not complete.");
    }
    if(!file.commit())throw std::runtime_error("Cannot confirm the certificate export.");
    QFile saved(destination);
    if(!saved.open(QIODevice::ReadOnly)||saved.readAll()!=pem)throw std::runtime_error("Cannot confirm the exported certificate. Export it again.");
}
void PublicCertificateIo::write(const QJsonObject &certificate,const QJsonObject &owned_state,const QString &destination,
    const std::shared_ptr<std::atomic<bool>> &cancelled) const {
    exportPublicCertificate(certificate,owned_state,destination,cancelled);
}
}
