#pragma once
#include "configuration_store.hpp"
#include <QDialog>
class QLabel;
class QPushButton;
namespace traverse {
class EndpointForm;
class SettingsDialog : public QDialog {
    std::shared_ptr<ConfigurationStore> store;
    std::optional<ConfigurationSnapshot> snapshot;
    std::filesystem::path path;
    EndpointForm *form;
    QLabel *feedback;
    QPushButton *save_button;
    bool busy=false;
    void readSettings();
    void saveSettings();
  public:
    explicit SettingsDialog(const QString &configuration,QWidget *parent=nullptr,
        std::shared_ptr<ConfigurationIo> operations=std::make_shared<ConfigurationIo>());
};
}
