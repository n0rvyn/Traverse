#include "public_certificate.hpp"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <cstdio>
int main(int argc,char **argv) {
    QCoreApplication application(argc,argv);QFile input;
    if(!input.open(stdin,QIODevice::ReadOnly))return 2;
    auto request=QJsonDocument::fromJson(input.readAll()).object();
    QJsonObject result;
    try {
        auto cancelled=std::make_shared<std::atomic<bool>>(request.value("cancelled").toBool());
        traverse::exportPublicCertificate(request.value("certificate").toObject(),request.value("state").toObject(),request.value("destination").toString(),cancelled);
        result={{"ok",true}};
    } catch(const std::exception &failure) {result={{"ok",false},{"error",QString::fromUtf8(failure.what())}};}
    auto bytes=QJsonDocument(result).toJson(QJsonDocument::Compact);std::fwrite(bytes.data(),1,size_t(bytes.size()),stdout);std::fputc('\n',stdout);return 0;
}
