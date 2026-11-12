#include "settings_dialog.hpp"
#include "endpoint_form.hpp"
#include "window_geometry.hpp"
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>
namespace traverse {
SettingsDialog::SettingsDialog(const QString &configuration,QWidget *parent,std::shared_ptr<ConfigurationIo> operations)
    :QDialog(parent),store(std::make_shared<ConfigurationStore>(configuration.toStdString(),std::move(operations))),path(configuration.toStdString()) {
    setObjectName("settingsDialog");setWindowTitle("Traverse Settings");
    auto layout=new QVBoxLayout(this);form=new EndpointForm(this,QString::fromStdString(path.parent_path().string()));
    auto scroll=new QScrollArea(this);scroll->setObjectName("settingsFields");scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);scroll->setFocusPolicy(Qt::NoFocus);
    scroll->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Ignored);scroll->setWidget(form);layout->addWidget(scroll,1);
    feedback=new QLabel("Loading settings…",this);feedback->setObjectName("saveFeedback");feedback->setWordWrap(true);layout->addWidget(feedback);
    auto buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel,this);
    save_button=buttons->button(QDialogButtonBox::Save);save_button->setObjectName("saveSettings");save_button->setEnabled(false);
    buttons->button(QDialogButtonBox::Cancel)->setObjectName("cancelSettings");
    layout->addWidget(buttons);connect(buttons,&QDialogButtonBox::rejected,this,&QDialog::reject);
    connect(save_button,&QPushButton::clicked,this,[this]{saveSettings();});
    form->edited=[this] {if(!busy&&snapshot){feedback->clear();save_button->setEnabled(true);}};
    form->setEnabled(false);
    fitDesktopWindow(*this,QSize(520,form->sizeHint().height()+feedback->sizeHint().height()+buttons->sizeHint().height()+
        layout->contentsMargins().top()+layout->contentsMargins().bottom()+2*layout->spacing()));
    QTimer::singleShot(0,this,[this]{readSettings();});
}
void SettingsDialog::readSettings() {
    busy=true;
    struct Read {std::optional<ConfigurationSnapshot> snapshot;QString error;};
    auto result=std::make_shared<Read>();auto source=store;
    auto thread=QThread::create([source,result] {
        try {result->snapshot=source->read();}
        catch(const std::exception &failure){result->error=QString::fromUtf8(failure.what());}
    });
    connect(thread,&QThread::finished,this,[this,result] {
        busy=false;snapshot=result->snapshot;
        if(snapshot){form->load(snapshot->document);form->setEnabled(true);save_button->setEnabled(true);feedback->clear();}
        else feedback->setText(result->error);
    });
    connect(thread,&QThread::finished,thread,&QObject::deleteLater);thread->start();
}
void SettingsDialog::saveSettings() {
    if(busy||!snapshot)return;
    nlohmann::json draft;
    try {draft=form->draft(path.parent_path().string());}
    catch(const std::exception &){return;}
    busy=true;form->setEnabled(false);save_button->setEnabled(false);feedback->setText("Saving…");
    auto result=std::make_shared<std::optional<ConfigurationSave>>();auto source=store;auto base=*snapshot;
    auto thread=QThread::create([source,result,base,draft] {*result=source->save(base,draft);});
    connect(thread,&QThread::finished,this,[this,result] {
        busy=false;const auto &saved=result->value();
        if(saved.outcome==SaveOutcome::Saved && saved.verified) {
            snapshot=saved.verified;form->load(snapshot->document);form->setEnabled(true);
            feedback->setText("Saved. Changes take effect the next time you launch Traverse.");
            save_button->setEnabled(false);
        } else {
            feedback->setText(QString::fromStdString(saved.detail));
            if(saved.outcome==SaveOutcome::NotSaved){form->setEnabled(true);save_button->setEnabled(true);}
            // An uncertain save must be reconciled from disk by reopening.
            else snapshot.reset();
        }
    });
    connect(thread,&QThread::finished,thread,&QObject::deleteLater);thread->start();
}
}
