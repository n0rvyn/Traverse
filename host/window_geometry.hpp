#pragma once
#include <QApplication>
#include <QScreen>
#include <QStyle>
#include <QWidget>
namespace traverse {
inline void fitDesktopWindow(QWidget &window,const QSize &preferred) {
    auto screen=window.screen();if(!screen)screen=QApplication::primaryScreen();
    auto available=screen?screen->availableGeometry().size():preferred;
    available.setHeight(qMax(1,available.height()-window.style()->pixelMetric(QStyle::PM_TitleBarHeight)));
    window.resize(preferred.boundedTo(available));
}
}
