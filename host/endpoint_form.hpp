#pragma once
#include <QWidget>
#include <functional>
#include <nlohmann/json.hpp>
class QComboBox;
class QLabel;
class QLineEdit;
namespace traverse {
// Shared native form. Persistence, issuance and active sharing stay outside.
class EndpointForm : public QWidget {
    QLineEdit *hostname, *port, *certificate, *key;
    QComboBox *method;
    QWidget *certificate_row, *key_row;
    QLabel *host_error, *port_error, *certificate_error, *key_error, *form_error;
    nlohmann::json base;
    QString configuration_directory;
    void methodChanged();
    void clearErrors();
    void updateWrapping();
    void resizeEvent(QResizeEvent *event) override;
  public:
    explicit EndpointForm(QWidget *parent=nullptr,const QString &directory={});
    void load(const nlohmann::json &document);
    nlohmann::json draft(const std::string &directory);
    std::function<void()> edited;
};
}
