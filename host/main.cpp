#include "sharing_window.hpp"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QTimer>
#include <cstdio>
#include <unistd.h>
int main(int argc, char **argv) {
    // Configured-host development entry; no install/default launch promotion.
    if (geteuid() == 0) { std::fputs("Run the host window as the desktop owner.\n", stderr); return 1; }
    QApplication application(argc, argv);
    application.setApplicationName("Traverse");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addOption({"prefix", "Private runtime prefix.", "directory"});
    parser.addOption({"config", "Existing schemaVersion1 configuration.", "file"});
    parser.process(application);
    auto prefix = QFileInfo(parser.value("prefix")).canonicalFilePath();
    auto configuration = QFileInfo(parser.value("config")).absoluteFilePath();
    if (!parser.isSet("prefix") || !parser.isSet("config") || prefix.isEmpty()) parser.showHelp(1);
    traverse::SharingWindow window(prefix, configuration);
    window.show();
    QTimer::singleShot(0, &window, [&window] { window.start(); });
    return application.exec();
}
