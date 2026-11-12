#include "sharing_window.hpp"
#include "setup_window.hpp"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QTimer>
#include <cstdio>
#include <cerrno>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
    // Development entry; package/default promotion has separate acceptance.
    if (geteuid() == 0) { std::fputs("Run the host window as the desktop owner.\n", stderr); return 1; }
    QApplication application(argc, argv);
    application.setApplicationName("Traverse");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addOption({"prefix", "Private runtime prefix.", "directory"});
    parser.addOption({"config", "SchemaVersion1 configuration; default XDG config location.", "file"});
    parser.process(application);
    auto prefix = QFileInfo(parser.value("prefix")).canonicalFilePath();
    if (!parser.isSet("prefix") || prefix.isEmpty()) parser.showHelp(1);
    QString configured=parser.value("config");
    if(!parser.isSet("config")) {
        if(!qEnvironmentVariableIsSet("XDG_CONFIG_HOME")&&!qEnvironmentVariableIsSet("HOME")) {
            std::fputs("Set HOME, XDG_CONFIG_HOME or --config.\n",stderr);return 1;
        }
        configured=(qEnvironmentVariableIsSet("XDG_CONFIG_HOME")?qEnvironmentVariable("XDG_CONFIG_HOME"):
            qEnvironmentVariable("HOME")+"/.config")+"/traverse/config.json";
    }
    auto configuration=QDir::cleanPath(QFileInfo(configured).absoluteFilePath());
    std::unique_ptr<traverse::SharingWindow> window;
    std::unique_ptr<traverse::SetupWindow> setup;
    auto launch=[&](const QString &file) {
        window=std::make_unique<traverse::SharingWindow>(prefix,file);window->show();
        QTimer::singleShot(0,window.get(),[&]{window->start();});
        if(setup)setup->close();
    };
    struct stat metadata{};
    if(lstat(configuration.toUtf8().constData(),&metadata)&&errno==ENOENT) {
        setup=std::make_unique<traverse::SetupWindow>(configuration);
        setup->configured=launch;setup->show();
    } else launch(configuration);
    return application.exec();
}
