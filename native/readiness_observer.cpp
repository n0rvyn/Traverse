#include "observer_policy.hpp"
#include "child.hpp"
#include <charconv>
#include <set>

namespace {
using nlohmann::json;
void fields(const json &value,std::initializer_list<const char *> keys) {
    if(!value.is_object() || value.size()!=keys.size())throw std::runtime_error("Invalid observer message");
    for(auto key:keys)if(!value.contains(key))throw std::runtime_error("Missing observer field");
}
void version(const json &value,int expected) {
    const auto &v=value.at("schemaVersion");
    if(!v.is_number_integer() || v!=expected)throw std::runtime_error("Invalid observer version");
}
json configuration(const std::string &path) {
    if(!std::filesystem::path(path).is_absolute())throw std::runtime_error("Absolute configuration path required");
    int raw=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(raw<0)throw std::runtime_error("Observer configuration unavailable");
    struct File { int fd;~File(){close(fd);} } file{raw};
    struct stat state{};
    if(fstat(raw,&state) || !S_ISREG(state.st_mode) || state.st_uid!=geteuid() || (state.st_mode&0077))
        throw std::runtime_error("Observer configuration must be owner-only regular file");
    std::string bytes;char buffer[4096];
    while(true) {
        auto count=read(raw,buffer,sizeof(buffer));
        if(count<0 && errno==EINTR)continue;
        if(count<0)throw std::runtime_error("Observer configuration unreadable");
        if(!count)break;
        bytes.append(buffer,count);
    }
    return json::parse(bytes);
}
class Observer {
    traverse::ObserverConfiguration policy;
    std::filesystem::path worker;
    const std::string instance=random_secret(16);
    std::optional<OwnedOperation::Result> run(const httplib::Request &request,const json &input) {
        if(stopping || request.is_connection_closed())return std::nullopt;
        OwnedOperation operation(worker,input.dump());
        while(!stopping && !request.is_connection_closed()) {
            if(auto result=operation.poll())return result;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        // Local object destruction stops/reaps before this handler thread exits.
        return std::nullopt;
    }
    const traverse::ObserverRegistration *authenticate(const httplib::Request &request) const {
        if(request.get_header_value_count("X-Traverse-Registration")!=1 ||
           request.get_header_value_count("Authorization")!=1 || request.has_header("Origin"))return nullptr;
        auto found=policy.registrations.find(request.get_header_value("X-Traverse-Registration"));
        if(found==policy.registrations.end())return nullptr;
        auto credential=request.get_header_value("Authorization");
        return equal_secret(credential,"Bearer "+found->second.token)?&found->second:nullptr;
    }
    void answer(httplib::Response &response,const char *status,int code=200) const {
        reply(response,{{"schemaVersion",1},{"observerInstance",instance},{"status",status}},code);
    }
    std::optional<json> resolve(const httplib::Request &request,const traverse::ObserverRegistration &registration) {
        auto result=run(request,registration.resolution_request());
        if(!result)return std::nullopt;
        auto row=json::parse(result->output);version(row,2);
        auto status=row.at("status").get<std::string>();
        if(status=="resolved" && result->exit_status==0) {
            fields(row,{"schemaVersion","status","addresses"});
            const auto &addresses=row.at("addresses");
            if(!addresses.is_array() || addresses.empty())throw std::runtime_error("Empty resolver result");
            std::set<std::string> checked;
            for(const auto &address:addresses) {
                auto pin=traverse::canonical_readiness_address(address.get<std::string>());
                if(!registration.resolution.allowed_addresses.count(pin) || !checked.insert(pin).second)
                    throw std::runtime_error("Invalid resolver authority");
            }
            return json{{"status","resolved"},{"addresses",checked}};
        }
        fields(row,{"schemaVersion","status"});
        if(result->exit_status!=0 && (status=="dnsFailed" || status=="dnsMismatch"))return json{{"status",status}};
        throw std::runtime_error("Invalid resolver completion");
    }
    void handle(const httplib::Request &request,httplib::Response &response,bool check) {
        const auto *registration=authenticate(request);
        if(!registration){answer(response,"unauthorized",403);return;}
        json body,verification;
        try {
            body=json::parse(request.body);version(body,1);
            if(check) {
                fields(body,{"schemaVersion","address","lease"});
                verification=registration->verification(body.at("address").get<std::string>(),body.at("lease"));
            } else fields(body,{"schemaVersion"});
        } catch(...) {answer(response,"invalidRequest",400);return;}
        try {
            auto resolved=resolve(request,*registration);
            if(!resolved)return;
            auto status=resolved->at("status").get<std::string>();
            if(status!="resolved"){answer(response,status.c_str());return;}
            if(!check) {
                reply(response,{{"schemaVersion",1},{"observerInstance",instance},{"status","resolved"},
                    {"addresses",resolved->at("addresses")}});return;
            }
            auto address=verification.at("target").at("address");
            auto addresses=resolved->at("addresses");
            if(std::find(addresses.begin(),addresses.end(),address)==addresses.end()){
                answer(response,"dnsMismatch");return;
            }
            auto completed=run(request,verification);
            if(!completed)return;
            auto result=json::parse(completed->output);version(result,1);
            status=result.at("status").get<std::string>();
            if(completed->exit_status==0 && status=="received") {
                fields(result,{"schemaVersion","status","receipt"});
                auto expected=traverse::parse_readiness_verification(verification);
                (void)traverse::parse_readiness_receipt({{"schemaVersion",1},{"receipt",result.at("receipt")}},expected.lease);
                reply(response,{{"schemaVersion",1},{"observerInstance",instance},{"status","received"},
                    {"address",address},{"addresses",addresses},{"receipt",result.at("receipt")}});return;
            }
            fields(result,{"schemaVersion","status"});
            static const std::set<std::string> failures={"connectionFailed","tlsFailed","httpRejected","invalidReceipt"};
            if(completed->exit_status!=0 && failures.count(status)){answer(response,status.c_str());return;}
            throw std::runtime_error("Invalid verifier completion");
        } catch(...) {answer(response,"internalFailure",503);}
    }
  public:
    Observer(traverse::ObserverConfiguration config,std::filesystem::path executable)
        :policy(std::move(config)),worker(std::move(executable)){}
    void serve() {
        httplib::SSLServer server(policy.certificate.c_str(),policy.private_key.c_str());
        if(!server.is_valid())throw std::runtime_error("Observer TLS configuration invalid");
        server.Post("/v1/resolve",[this](const auto &request,auto &response){handle(request,response,false);});
        server.Post("/v1/check",[this](const auto &request,auto &response){handle(request,response,true);});
        if(!server.bind_to_port(policy.listen_address,policy.port))throw std::runtime_error("Observer listener unavailable");
        std::mutex mutex;std::condition_variable changed;bool entered=false,exited=false;bool success=false;
        server.set_start_handler([&]{std::lock_guard lock(mutex);entered=true;changed.notify_all();});
        std::thread listener([&]{bool ok=server.listen_after_bind();std::lock_guard lock(mutex);success=ok;exited=true;changed.notify_all();});
        struct Join {httplib::Server &server;std::thread &thread;~Join(){server.stop();if(thread.joinable())thread.join();}} join{server,listener};
        {
            std::unique_lock lock(mutex);changed.wait(lock,[&]{return entered || exited;});
            if(!entered)throw std::runtime_error("Observer listener did not start");
        }
        bool listener_failed=false;
        while(!stopping) {
            if(!server.is_running()){listener_failed=true;stopping=true;break;}
            std::unique_lock lock(mutex);
            if(changed.wait_for(lock,std::chrono::milliseconds(20),[&]{return exited;}))break;
        }
        server.stop();listener.join();
        if(listener_failed || (!stopping && !success))throw std::runtime_error("Observer listener failed");
    }
};
}
int main(int argc,char **argv) {
    try {
        std::string path;bool guarded=false;
        for(int i=1;i<argc;++i) {
            std::string key=argv[i];
            if(i+1>=argc)throw std::runtime_error("Observer option value missing");
            std::string value=argv[++i];
            if(key=="--config" && path.empty())path=value;
            else if(key=="--supervisor-pid" && !guarded) {
                pid_t parent=-1;auto parsed=std::from_chars(value.data(),value.data()+value.size(),parent);
                if(parsed.ec!=std::errc{} || parsed.ptr!=value.data()+value.size() || parent<=1 ||
                   prctl(PR_SET_PDEATHSIG,SIGTERM) || getppid()!=parent)throw std::runtime_error("Observer supervisor unavailable");
                guarded=true;
            } else throw std::runtime_error("Unknown or duplicate observer option");
        }
        if(path.empty())throw std::runtime_error("Observer configuration required");
        auto config=traverse::ObserverConfiguration::parse(configuration(path));
        auto worker=std::filesystem::canonical("/proc/self/exe").parent_path()/"traverse-readiness-verifier";
        std::signal(SIGTERM,signal_stop);std::signal(SIGINT,signal_stop);std::signal(SIGPIPE,SIG_IGN);
        Observer observer(std::move(config),worker);observer.serve();return 0;
    } catch(...) {
        std::cerr<<"Observer startup or listener failed\n";return 1;
    }
}
