#pragma once
#include <QJsonObject>
#include <QString>
namespace traverse {
struct ConnectionFeedback {
    QString url,media,notification_key,notification_body;
    bool startup_failure=false;
};
ConnectionFeedback connection_feedback(const QJsonObject &state,qint64 monotonic_now);
}
