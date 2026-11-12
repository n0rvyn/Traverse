#include "setup_window.hpp"
#include "endpoint_form.hpp"
#include "window_geometry.hpp"
#include <QHBoxLayout>
#include <QCloseEvent>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QThread>
#include <QVBoxLayout>
namespace traverse {
SetupWindow::SetupWindow(QString file,QWidget *parent,std::shared_ptr<ConfigurationIo> operations)
    :QWidget(parent),store(std::make_shared<ConfigurationStore>(file.toStdString(),std::move(operations))),configuration(std::move(file)) {
    setObjectName("setupWindow");setWindowTitle("Traverse setup");
    auto layout=new QVBoxLayout(this);form=new EndpointForm(this,QString::fromStdString(std::filesystem::path(configuration.toStdString()).parent_path().string()));
    auto scroll=new QScrollArea(this);scroll->setObjectName("setupFields");scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);scroll->setFocusPolicy(Qt::NoFocus);
    scroll->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Ignored);scroll->setWidget(form);layout->addWidget(scroll,1);
    feedback=new QLabel(this);feedback->setObjectName("setupFeedback");feedback->setWordWrap(true);layout->addWidget(feedback);
    auto footer=new QHBoxLayout;footer->addStretch();start_button=new QPushButton("Start sharing",this);
    start_button->setObjectName("startSharing");footer->addWidget(start_button);layout->addLayout(footer);
    connect(start_button,&QPushButton::clicked,this,[this]{startSharing();});
    form->edited=[this]{if(!busy)feedback->clear();};
    fitDesktopWindow(*this,QSize(520,form->sizeHint().height()+feedback->sizeHint().height()+start_button->sizeHint().height()+
        layout->contentsMargins().top()+layout->contentsMargins().bottom()+2*layout->spacing()));
}
void SetupWindow::startSharing() {
    if(busy||closed)return;
    nlohmann::json draft;
    try {draft=form->draft(std::filesystem::path(configuration.toStdString()).parent_path().string());}
    catch(const std::exception &){return;}
    busy=true;form->setEnabled(false);start_button->setEnabled(false);feedback->setText("Preparing sharing…");
    auto source=store;auto result=std::make_shared<std::optional<ConfigurationSave>>();
    auto thread=QThread::create([source,result,draft]{*result=source->create(draft);});
    connect(thread,&QThread::finished,this,[this,result] {
        if(closed)return;
        busy=false;const auto &created=result->value();
        if(created.outcome==SaveOutcome::Saved&&created.verified) {
            if(configured)configured(configuration);
        } else {
            feedback->setText(QString::fromStdString(created.detail));
            if(created.outcome==SaveOutcome::NotSaved){form->setEnabled(true);start_button->setEnabled(true);}
            else feedback->setText("Cannot confirm setup. Close and reopen Traverse to check the saved settings.");
        }
    });
    connect(thread,&QThread::finished,thread,&QObject::deleteLater);thread->start();
}
void SetupWindow::closeEvent(QCloseEvent *event) {
    closed=true;QWidget::closeEvent(event);
}
}
