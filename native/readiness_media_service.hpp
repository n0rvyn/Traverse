#pragma once
#include <filesystem>
#include <memory>
#include <string>
namespace httplib { class Server; }
namespace traverse {
// Internal routes remain opt-in until the installed low-port authority gate.
class ReadinessMediaService {
    struct Impl;
    std::unique_ptr<Impl> impl;
  public:
    ReadinessMediaService(std::filesystem::path worker,unsigned short port,std::string probe_broker={});
    ~ReadinessMediaService();
    void owner_routes(httplib::Server &);
    void public_routes(httplib::Server &,const std::string &escaped_prefix);
    void preempt();
    void owner_state(bool armed,bool paired);
    void stop();
};
}
