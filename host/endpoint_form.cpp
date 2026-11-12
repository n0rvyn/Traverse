#include "endpoint_form.hpp"
#include "endpoint_settings.hpp"
#include <QComboBox>
#include <QDir>
#include <QFileInfo>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QResizeEvent>
#include <QVBoxLayout>
#include <stdexcept>
namespace traverse {
EndpointForm::EndpointForm(QWidget *parent,const QString &directory):QWidget(parent),configuration_directory(directory) {
    setObjectName("endpointForm");
    auto layout=new QFormLayout(this);
    layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    layout->setRowWrapPolicy(QFormLayout::WrapLongRows);
    auto field=[&](const char *name,QLineEdit *&input,QLabel *&error,bool browse) {
        auto container=new QWidget(this);auto column=new QVBoxLayout(container);
        column->setContentsMargins(0,0,0,0);auto row=new QHBoxLayout;
        input=new QLineEdit(container);input->setObjectName(name);row->addWidget(input);
        if(browse) {
            auto button=new QPushButton("Browse…",container);button->setObjectName(QString(name)+"Browse");
            row->addWidget(button);
            connect(button,&QPushButton::clicked,this,[this,input] {
                auto initial=input->text();
                if(!initial.isEmpty()&&QFileInfo(initial).isRelative()&&!configuration_directory.isEmpty())
                    initial=QDir(configuration_directory).absoluteFilePath(initial);
                auto directory=initial.isEmpty()?configuration_directory:QFileInfo(initial).absolutePath();
                if(!QDir(directory).exists())directory=QDir::homePath();
                auto picker=new QFileDialog(this,input==key?"Select private key file":"Select certificate file",directory);
                picker->setObjectName(input->objectName()+"Picker");picker->setFileMode(QFileDialog::ExistingFile);
                picker->setWindowModality(Qt::NonModal);picker->setAttribute(Qt::WA_DeleteOnClose);
                if(!initial.isEmpty())picker->selectFile(initial);
                connect(picker,&QFileDialog::fileSelected,this,[input](const QString &selected){if(input->isEnabled())input->setText(selected);});
                picker->show();
            });
        }
        error=new QLabel(container);error->setObjectName(QString(name)+"Error");
        error->setWordWrap(true);error->hide();column->addLayout(row);column->addWidget(error);
        connect(input,&QLineEdit::textChanged,this,[this] {clearErrors();if(edited)edited();});
        return container;
    };
    layout->addRow("Hostname/address",field("hostnameField",hostname,host_error,false));
    layout->addRow("Port",field("portField",port,port_error,false));
    method=new QComboBox(this);method->setObjectName("certificateMethod");
    method->addItem("Generate locally","local");method->addItem("Use existing certificates","supplied");
    layout->addRow("Certificate method",method);
    certificate_row=field("certificateField",certificate,certificate_error,true);
    key_row=field("privateKeyField",key,key_error,true);
    layout->addRow("Certificate",certificate_row);layout->addRow("Private key",key_row);
    hostname->setAccessibleName("Hostname/address");port->setAccessibleName("Port");
    certificate->setAccessibleName("Certificate");key->setAccessibleName("Private key");
    form_error=new QLabel(this);form_error->setObjectName("formError");form_error->setWordWrap(true);
    layout->addRow(form_error);form_error->hide();
    connect(method,qOverload<int>(&QComboBox::currentIndexChanged),this,[this] {
        methodChanged();clearErrors();if(edited)edited();
    });
    load({{"schemaVersion",1},{"domain",""},{"port",443},{"certificateSettings",{{"mode","local"}}}});
}
void EndpointForm::clearErrors() {
    for(auto label:{host_error,port_error,certificate_error,key_error,form_error}) {label->clear();label->hide();}
}
void EndpointForm::methodChanged() {
    bool supplied=method->currentData().toString()=="supplied";
    auto layout=qobject_cast<QFormLayout*>(this->layout());
    // Hide the corresponding labels too, using Qt6.2-compatible APIs.
    for(auto row:{certificate_row,key_row}) {
        row->setVisible(supplied);
        if(auto label=layout->labelForField(row))label->setVisible(supplied);
    }
    updateWrapping();
}
void EndpointForm::updateWrapping() {
    auto form=qobject_cast<QFormLayout*>(layout());
    int labels=0,fields=0;
    for(int row=0;row<form->rowCount();++row) {
        auto label=form->itemAt(row,QFormLayout::LabelRole);
        auto field=form->itemAt(row,QFormLayout::FieldRole);
        if(!label||!field||field->isEmpty())continue;
        labels=qMax(labels,label->sizeHint().width());fields=qMax(fields,field->sizeHint().width());
    }
    auto margins=form->contentsMargins();
    auto required=labels+fields+qMax(0,form->horizontalSpacing())+margins.left()+margins.right();
    form->setRowWrapPolicy(width()<required?QFormLayout::WrapAllRows:QFormLayout::WrapLongRows);
}
void EndpointForm::resizeEvent(QResizeEvent *event) {QWidget::resizeEvent(event);updateWrapping();}
void EndpointForm::load(const nlohmann::json &document) {
    base=document;
    hostname->setText(QString::fromStdString(base.value("domain",std::string{})));
    port->setText(QString::number(base.value("port",443)));
    certificate->setText(QString::fromStdString(base.value("certificate",std::string{})));
    key->setText(QString::fromStdString(base.value("privateKey",std::string{})));
    auto mode=base.contains("certificateSettings")?base.at("certificateSettings").at("mode").get<std::string>():"supplied";
    auto automatic=method->findData("automatic");
    if(mode=="automatic"&&automatic<0)method->addItem("Automatic (configured)","automatic");
    if(mode!="automatic"&&automatic>=0)method->removeItem(automatic);
    method->setCurrentIndex(method->findData(QString::fromStdString(mode)));
    methodChanged();clearErrors();
}
nlohmann::json EndpointForm::draft(const std::string &directory) {
    clearErrors();
    auto reject=[](QLineEdit *field,QLabel *label,const QString &message) {
        label->setText(message);label->show();field->setFocus();throw std::runtime_error("Invalid form field");
    };
    try {EndpointSettings::normalize_host(hostname->text().toStdString());}
    catch(const std::exception &failure){reject(hostname,host_error,QString::fromUtf8(failure.what()));}
    bool numeric=false;auto value=port->text().toUInt(&numeric);
    if(!numeric || value<1 || value>65535)reject(port,port_error,"Enter a port from 1 to 65535.");
    auto result=base;result["domain"]=hostname->text().toStdString();result["port"]=value;
    auto mode=method->currentData().toString();
    if(mode=="supplied") {
        if(certificate->text().isEmpty())reject(certificate,certificate_error,"Select a certificate file.");
        if(key->text().isEmpty())reject(key,key_error,"Select a private key file.");
        result.erase("certificateSettings");result["certificate"]=certificate->text().toStdString();result["privateKey"]=key->text().toStdString();
    } else if(mode=="local") {
        result.erase("certificate");result.erase("privateKey");result["certificateSettings"]={{"mode","local"}};
    }
    try {EndpointSettings::parse(result,"",directory);}
    catch(const std::exception &failure) {form_error->setText(QString::fromUtf8(failure.what()));form_error->show();throw;}
    return result;
}
}
