#pragma once
#include "owner_client.hpp"
#include "public_certificate.hpp"
#include <QLabel>
#include <QPushButton>
#include <QPointer>
#include <QWidget>

class QFileDialog;
namespace traverse {
class SettingsDialog;
class SharingWindow : public QWidget {
    friend class SharingFeedbackTests;
    OwnerClient client;
    QLabel *status, *url, *code, *url_check, *media_check;
    QPushButton *copy_url, *copy_code, *new_code, *stop_button;
    QString running_url, available_code;
    QString notified_check;
    bool startup_notified=false;
    bool closing = false;
    bool sharing_ended = false;
    bool refreshing = false;
    QTimer code_expiry;
    QString configuration_file;
    QPointer<SettingsDialog> settings_dialog;
    QPushButton *export_ca;
    QLabel *trust_instruction, *export_feedback;
    QPointer<QFileDialog> certificate_picker;
    std::shared_ptr<PublicCertificateIo> public_output;
    std::shared_ptr<std::atomic<bool>> export_cancelled;
    QString export_destination;
    bool export_available=false,export_pending=false,export_writing=false;
    void choosePublicCertificate();
    void publicCertificateReply(bool ok,const QJsonObject &certificate,const QJsonObject &state);
    void updateState(const QJsonObject &state);
    void notifyFailure(const QString &body,const QString &identity,bool startup=false);
    void stopSharing();
    void closeEvent(QCloseEvent *event) override;

  public:
    SharingWindow(const QString &prefix, const QString &configuration,
        std::shared_ptr<PublicCertificateIo> output=std::make_shared<PublicCertificateIo>());
    ~SharingWindow() override;
    void start();
};
} // namespace traverse
