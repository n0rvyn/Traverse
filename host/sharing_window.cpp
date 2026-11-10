#include "sharing_window.hpp"
#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QFont>
#include <QHBoxLayout>
#include <QScreen>
#include <QScrollArea>
#include <QStyle>
#include <QUrl>
#include <QVBoxLayout>
#include <chrono>
#include <limits>

namespace traverse {
SharingWindow::SharingWindow(const QString &prefix, const QString &configuration)
    : client(prefix, configuration, this) {
    setWindowTitle("Traverse");
    setObjectName("sharingWindow");
    auto layout = new QVBoxLayout(this);
    layout->setContentsMargins(20,20,20,20);
    layout->setSpacing(14);
    auto heading = new QHBoxLayout;
    auto title = new QLabel("Traverse", this);
    auto title_font = title->font(); title_font.setBold(true); title->setFont(title_font);
    auto settings = new QPushButton("Settings", this);
    settings->setObjectName("settingsButton");
    // Internal Task1 entry only. Task2 supplies the pending-approved form;
    // this incomplete window is not installed/promoted as the product entry.
    settings->setEnabled(false);
    heading->addWidget(title); heading->addStretch(); heading->addWidget(settings);
    layout->addLayout(heading);
    status = new QLabel("Starting sharing", this); status->setObjectName("connectionStatus");
    auto status_font = status->font(); status_font.setPointSizeF(status_font.pointSizeF()*1.3);
    status_font.setBold(true); status->setFont(status_font); status->setWordWrap(true);
    status->setAccessibleName("Connection status"); layout->addWidget(status);
    auto body = new QWidget(this);
    auto details = new QVBoxLayout(body);
    details->setContentsMargins(0,0,0,0); details->setSpacing(14);
    auto scroll = new QScrollArea(this); scroll->setObjectName("sharingDetails");
    scroll->setWidgetResizable(true); scroll->setFrameShape(QFrame::NoFrame);
    scroll->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Ignored);
    scroll->setWidget(body); layout->addWidget(scroll,1);
    auto url_label = new QLabel("Remote URL", this); details->addWidget(url_label);
    auto url_row = new QHBoxLayout;
    url = new QLabel(this); url->setObjectName("remoteUrl"); url->setWordWrap(true);
    url->setTextFormat(Qt::PlainText); url->setTextInteractionFlags(Qt::TextSelectableByMouse);
    copy_url = new QPushButton("Copy", this); copy_url->setObjectName("copyUrl");
    copy_url->setAccessibleName("Copy remote URL"); copy_url->setEnabled(false);
    url->setMinimumWidth(0); url->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
    url_row->addWidget(url,1); url_row->addWidget(copy_url); details->addLayout(url_row);
    auto code_label = new QLabel("Pairing code", this); details->addWidget(code_label);
    auto code_row = new QHBoxLayout;
    code = new QLabel(this); code->setObjectName("pairingCode"); code->setTextFormat(Qt::PlainText);
    code->setWordWrap(true); code->setTextInteractionFlags(Qt::TextSelectableByMouse);
    copy_code = new QPushButton("Copy", this); copy_code->setObjectName("copyCode");
    copy_code->setAccessibleName("Copy pairing code"); copy_code->setEnabled(false);
    new_code = new QPushButton("New code", this); new_code->setObjectName("newCode"); new_code->setEnabled(false);
    code_row->addWidget(code,1); code_row->addWidget(copy_code); code_row->addWidget(new_code);
    details->addLayout(code_row);
    auto checks_label = new QLabel("Connection checks", this);
    auto checks_font = checks_label->font(); checks_font.setBold(true); checks_label->setFont(checks_font);
    details->addWidget(checks_label);
    url_check = new QLabel("URL: Checking…", this); url_check->setObjectName("urlCheck");
    media_check = new QLabel("Media: Waiting for Chrome", this); media_check->setObjectName("mediaCheck");
    url_check->setWordWrap(true); media_check->setWordWrap(true);
    details->addWidget(url_check); details->addWidget(media_check); details->addStretch();
    auto footer = new QHBoxLayout; footer->addStretch();
    stop_button = new QPushButton("Stop sharing", this); stop_button->setObjectName("stopSharing");
    stop_button->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    footer->addWidget(stop_button); layout->addLayout(footer);
    connect(copy_url, &QPushButton::clicked, this, [this] {
        if (!running_url.isEmpty()) QApplication::clipboard()->setText(running_url);
    });
    connect(copy_code, &QPushButton::clicked, this, [this] {
        if (!available_code.isEmpty()) QApplication::clipboard()->setText(available_code);
    });
    connect(new_code, &QPushButton::clicked, this, [this] {
        code_expiry.stop();
        refreshing=true;available_code.clear();copy_code->setEnabled(false);new_code->setEnabled(false);
        code->setText("Updating…");client.newCode();
    });
    connect(stop_button, &QPushButton::clicked, this, [this] { stopSharing(); });
    code_expiry.setSingleShot(true);code_expiry.setTimerType(Qt::PreciseTimer);
    connect(&code_expiry,&QTimer::timeout,this,[this] {
        available_code.clear();copy_code->setEnabled(false);code->setText("Expired");
    });
    client.stateChanged = [this](const QJsonObject &state) { updateState(state); };
    client.codeRefreshed = [this](bool) { refreshing=false; };
    client.failed = [this](const QString &message) {
        if (!closing) { status->setText("Sharing failed"); url_check->setText(message); }
    };
    client.stopped = [this](int result) {
        sharing_ended=true;
        if (closing) { close(); QApplication::quit(); }
        else { status->setText(result == 0 ? "Sharing stopped" : "Sharing failed"); }
    };
    auto screen = QApplication::primaryScreen();
    auto available = screen ? screen->availableGeometry().size() : QSize(520,440);
    available.rheight() -= style()->pixelMetric(QStyle::PM_TitleBarHeight);
    resize(QSize(520,440).boundedTo(available));
}
void SharingWindow::updateState(const QJsonObject &state) {
    code_expiry.stop();
    available_code.clear(); copy_code->setEnabled(false); new_code->setEnabled(false);
    if (closing) return;
    if (state.isEmpty()) {
        code->setText("Unavailable"); status->setText("Sharing status unavailable");
        url_check->setText("URL: Status unavailable"); media_check->setText("Media: Status unavailable");
        return;
    }
    auto configured = state.value("configuredUrl").toString();
    QUrl address(configured);
    if (!configured.isEmpty() && address.isValid() && address.scheme() == "https") {
        running_url = configured; url->setText(running_url); copy_url->setEnabled(true);
    }
    auto authority = state.value("authority").toObject();
    auto code_status = authority.value("codeStatus").toString();
    if (refreshing) code->setText("Updating…");
    else if (code_status == "available") {
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        auto expires=authority.value("expiresMonotonicMs").toInteger(-1);
        auto remaining=expires-now;
        if(remaining>=0 && remaining<std::numeric_limits<int>::max()) {
            available_code=authority.value("code").toString();code->setText(available_code);
            copy_code->setEnabled(!available_code.isEmpty());
            code_expiry.start(int(remaining)+1);
        } else code->setText(expires>=0&&remaining<0?"Expired":"Unavailable");
    } else code->setText(code_status == "used" ? "Used" : code_status == "expired" ? "Expired" : "Unavailable");
    new_code->setEnabled(!refreshing && authority.value("armed").toBool() && !authority.value("paired").toBool());
    auto peer = state.value("peer").toObject();
    bool connected = peer.value("peerActive").toBool() && peer.value("controlOpen").toBool() &&
                     peer.value("rtcState").toString() == "connected";
    auto phase = state.value("phase").toString();
    status->setText(phase == "failed" ? "Sharing failed" : phase != "ready" ? "Starting sharing" :
                    connected ? "Connected" : authority.value("paired").toBool() ?
                    "Waiting for Chrome to reconnect" : "Waiting for Chrome");
    auto local = state.value("localHttps").toObject().value("status").toString();
    url_check->setText(local == "passed" ? "URL: Local HTTPS verified. External check unavailable" :
                       local == "pending" ? "URL: Checking…" : "URL: Status unavailable");
    media_check->setText(connected ? "Media: Connected" : "Media: Waiting for Chrome");
}
void SharingWindow::stopSharing() {
    if (closing) return;
    closing = true; available_code.clear(); code->setText("Unavailable");
    code_expiry.stop();
    copy_code->setEnabled(false); new_code->setEnabled(false);
    status->setText("Stopping sharing"); client.stop();
}
void SharingWindow::closeEvent(QCloseEvent *event) {
    if(sharing_ended) { event->accept(); return; }
    event->ignore(); stopSharing();
}
void SharingWindow::start() { client.start(); }
} // namespace traverse
