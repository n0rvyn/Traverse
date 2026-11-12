#pragma once
#include "configuration_store.hpp"
#include <QWidget>
#include <functional>
class QLabel;
class QPushButton;
class QCloseEvent;
namespace traverse {
class EndpointForm;
class SetupWindow : public QWidget {
    std::shared_ptr<ConfigurationStore> store;
    QString configuration;
    EndpointForm *form;
    QLabel *feedback;
    QPushButton *start_button;
    bool busy=false,closed=false;
    void startSharing();
    void closeEvent(QCloseEvent *event) override;
  public:
    explicit SetupWindow(QString file,QWidget *parent=nullptr,
        std::shared_ptr<ConfigurationIo> operations=std::make_shared<ConfigurationIo>());
    std::function<void(const QString &)> configured;
};
}
