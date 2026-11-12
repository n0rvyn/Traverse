#include "readiness_agent.hpp"
#include "observer_settings.hpp"
#include "owner_state.hpp"
#include "readiness_verifier.hpp"
#include <set>

namespace traverse {
namespace {
void fields(const json &value,std::initializer_list<const char *> names) {
    if(!value.is_object() || value.size()!=names.size())throw std::runtime_error("Invalid agent shape");
    for(auto name:names)if(!value.contains(name))throw std::runtime_error("Missing agent field");
}
void version(const json &value) {
    const auto &v=value.at("schemaVersion");
    if(!v.is_number_integer() || v!=1)throw std::runtime_error("Invalid agent version");
}
std::string hex(const json &value,const char *key,size_t count) {
    auto text=value.at(key).get<std::string>();
    if(text.size()!=count || text.find_first_not_of("0123456789abcdef")!=std::string::npos)
        throw std::runtime_error("Invalid agent identifier");
    return text;
}
std::set<std::string> addresses(const json &value) {
    if(!value.is_array() || value.empty())throw std::runtime_error("Invalid observer address set");
    std::set<std::string> result;
    for(const auto &item:value) {
        auto text=item.get<std::string>();
        if(canonical_readiness_address(text)!=text || !result.insert(text).second)
            throw std::runtime_error("Invalid observer address");
    }
    return result;
}
class Transport {
    ObserverSettings settings;
    std::string credential,ca;
  public:
    explicit Transport(const json &value):settings(ObserverSettings::parse(value,"")),
        credential(read_observer_credential(settings.token_file)),
        ca(settings.ca_file.empty()?"":read_observer_ca(settings.ca_file)) {
        if(!settings.ca_file.empty() && ca.empty())throw std::runtime_error("Observer CA empty");
    }
    json post(const char *route,const json &body) const {
        httplib::SSLClient client(settings.host,settings.port);
        client.enable_server_certificate_verification(true);
        client.enable_server_hostname_verification(true);
        client.set_follow_location(false);client.set_decompress(false);client.set_keep_alive(false);
        if(!ca.empty())client.load_ca_cert_store(ca.data(),ca.size());
        httplib::Headers headers={{"Authorization","Bearer "+credential},
            {"X-Traverse-Registration",settings.registration_id}};
        auto response=client.Post(route,headers,body.dump(),"application/json");
        if(!response)throw std::runtime_error("Observer unavailable");
        auto result=json::parse(response->body);version(result);
        hex(result,"observerInstance",32);
        auto status=result.at("status").get<std::string>();
        if(response->status!=200 && !(response->status==403 && status=="unauthorized") &&
           !(response->status==503 && status=="internalFailure"))throw std::runtime_error("Observer rejected");
        return result;
    }
};
struct Owner {
    std::string socket;
    pid_t pid;
    explicit Owner(const json &value) {
        fields(value,{"socket","pid"});socket=value.at("socket").get<std::string>();
        const auto &id=value.at("pid");
        if(!id.is_number_integer() || id<=1 || id>std::numeric_limits<pid_t>::max())
            throw std::runtime_error("Invalid owner PID");
        pid=id.get<pid_t>();
        if(!std::filesystem::path(socket).is_absolute() || socket.find('\0')!=std::string::npos)
            throw std::runtime_error("Invalid owner socket");
    }
    std::pair<int,json> call(const char *route,const json &body) const {
        auto result=owned_json_request(socket,pid,route,&body);
        result.second=validate_owner_state(std::move(result.second),pid);
        return result;
    }
};
json event(const char *kind,const std::string &status) {
    return {{"schemaVersion",1},{"event",kind},{"status",status}};
}
std::string failure(const json &row) {
    fields(row,{"schemaVersion","observerInstance","status"});
    static const std::set<std::string> allowed={"dnsFailed","dnsMismatch","connectionFailed", "tlsFailed",
        "httpRejected","invalidReceipt","unauthorized","internalFailure"};
    auto status=row.at("status").get<std::string>();
    if(!allowed.count(status))throw std::runtime_error("Invalid observer status");
    return status;
}
ReadinessChallenge::Lease lease(const json &value,const std::string &id) {
    fields(value,{"instance","id","token","nonce"});
    ReadinessChallenge::Lease result;
    result.instance=hex(value,"instance",32);result.id=hex(value,"id",32);
    result.token=hex(value,"token",64);result.nonce=hex(value,"nonce",64);
    if(result.id!=id)throw std::runtime_error("Wrong owner reservation");
    return result;
}
}
void run_readiness_agent(const json &request,const std::function<void(const json &)> &emit) {
    version(request);auto operation=request.at("operation").get<std::string>();
    if(operation=="resolve") {
        fields(request,{"schemaVersion","operation","observer"});
        Transport transport(request.at("observer"));auto row=transport.post("/v1/resolve",{{"schemaVersion",1}});
        auto status=row.at("status").get<std::string>();auto result=event("resolved",status);
        if(status=="resolved") {
            fields(row,{"schemaVersion","observerInstance","status","addresses"});
            result["addresses"]=addresses(row.at("addresses"));
        } else result["status"]=failure(row);
        result["observerInstance"]=row.at("observerInstance");emit(result);return;
    }
    if(operation=="check") {
        fields(request,{"schemaVersion","operation","observer","owner","observerInstance","probes"});
        Transport transport(request.at("observer"));Owner owner(request.at("owner"));
        auto instance=hex(request,"observerInstance",32);
        const auto &probes=request.at("probes");
        if(!probes.is_array() || probes.empty())throw std::runtime_error("Missing probe batch");
        std::set<std::string> expected,ids;
        for(const auto &probe:probes) {
            fields(probe,{"id","address"});auto id=hex(probe,"id",32);
            auto address=probe.at("address").get<std::string>();
            if(canonical_readiness_address(address)!=address || !expected.insert(address).second || !ids.insert(id).second)
                throw std::runtime_error("Duplicate or invalid probe");
        }
        std::mutex writer;std::vector<std::thread> workers;
        // Join even if creation of a later worker throws. Parent owns all IDs
        // already; it must finish/cancel the batch after every exit path.
        struct Join {std::vector<std::thread> &items;~Join(){for(auto &thread:items)if(thread.joinable())thread.join();}} join{workers};
        for(const auto &probe:probes)workers.emplace_back([&,probe] {
            auto result=event("address","agentFailed");result["id"]=probe.at("id");result["address"]=probe.at("address");
            try {
                auto reserved=owner.call("/readiness/reserve",{{"schemaVersion",1},{"id",probe.at("id")}});
                if(reserved.first!=200)throw std::runtime_error("Reservation failed");
                auto authority=lease(reserved.second.at("lease"),probe.at("id").get<std::string>());
                auto row=transport.post("/v1/check",{{"schemaVersion",1},{"address",probe.at("address")},{"lease",reserved.second.at("lease")}});
                if(row.at("observerInstance")!=instance)throw std::runtime_error("Observer changed");
                auto status=row.at("status").get<std::string>();
                if(status=="received") {
                    fields(row,{"schemaVersion","observerInstance","status","address","addresses","receipt"});
                    if(row.at("address")!=probe.at("address") || addresses(row.at("addresses"))!=expected)
                        throw std::runtime_error("Observer address set changed");
                    (void)parse_readiness_receipt({{"schemaVersion",1},{"receipt",row.at("receipt")}},authority);
                    result["status"]="received";result["receipt"]=row.at("receipt");
                } else result["status"]=failure(row);
            } catch(...) {}
            std::lock_guard lock(writer);emit(result);
        });
        return;
    }
    if(operation=="finish") {
        fields(request,{"schemaVersion","operation","owner","probes"});Owner owner(request.at("owner"));
        const auto &probes=request.at("probes");
        if(!probes.is_array())throw std::runtime_error("Invalid cleanup batch");
        std::set<std::string> ids;
        for(const auto &probe:probes) {
            if(probe.contains("receipt"))fields(probe,{"id","receipt"});else fields(probe,{"id"});
            if(!ids.insert(hex(probe,"id",32)).second)throw std::runtime_error("Duplicate cleanup ID");
        }
        for(const auto &probe:probes) {
            auto result=event("finished","notObserved");result["id"]=probe.at("id");result["cancelled"]=false;
            json body={{"schemaVersion",1},{"id",probe.at("id")}};
            try {
                if(probe.contains("receipt")) {
                    auto inspected=owner.call("/readiness/inspect",body);
                    if(inspected.first==200 && inspected.second.at("probe").at("id")==probe.at("id") &&
                       inspected.second.at("probe").at("state")=="observed" &&
                       inspected.second.at("probe").at("receipt")==probe.at("receipt"))result["status"]="verified";
                    else result["status"]="receiptMismatch";
                }
            } catch(...) {result["status"]="ownerUnavailable";}
            try {
                auto cancelled=owner.call("/readiness/cancel",body);
                result["cancelled"]=cancelled.first==200 && cancelled.second.at("ok")==true;
            } catch(...) {}
            emit(result);
        }
        return;
    }
    throw std::runtime_error("Unknown agent operation");
}
}
