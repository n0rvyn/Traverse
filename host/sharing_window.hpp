#pragma once
#include "owner_client.hpp"
#include <QLabel>
#include <QPushButton>
#include <QWidget>

namespace traverse {
class SharingWindow : public QWidget {
    OwnerClient client;
    QLabel *status, *url, *code, *url_check, *media_check;
    QPushButton *copy_url, *copy_code, *new_code, *stop_button;
    QString running_url, available_code;
    bool closing = false;
    bool sharing_ended = false;
    bool refreshing = false;
    QTimer code_expiry;
    void updateState(const QJsonObject &state);
    void stopSharing();
    void closeEvent(QCloseEvent *event) override;

  public:
    SharingWindow(const QString &prefix, const QString &configuration);
    void start();
};
} // namespace traverse
