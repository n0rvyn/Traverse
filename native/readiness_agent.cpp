#include "readiness_agent.hpp"
#include "observer_settings.hpp"
#include "owner_state.hpp"
#include "readiness_verifier.hpp"
#include "name_resolution.hpp"
#include <set>
#include <netdb.h>
#include <arpa/inet.h>

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
    std::set<std::string> pins() const {
        addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
        addrinfo *raw=nullptr;
        if(getaddrinfo(settings.host.c_str(),nullptr,&hints,&raw))throw std::runtime_error("Observer resolution failed");
        std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> list(raw,freeaddrinfo);
        std::set<std::string> result;
        for(auto *entry=raw;entry;entry=entry->ai_next) {
            char address[NI_MAXHOST];
            if(getnameinfo(entry->ai_addr,entry->ai_addrlen,address,sizeof(address),nullptr,0,NI_NUMERICHOST))
                throw std::runtime_error("Observer address unavailable");
            result.insert(canonical_readiness_address(address));
        }
        if(result.empty())throw std::runtime_error("Observer resolution empty");
        return result;
    }
    json post(const char *route,const json &body,int expected_version=1,const std::string &pin={}) const {
        httplib::SSLClient client(settings.host,settings.port);
        if(!pin.empty())client.set_hostname_addr_map({{settings.host,pin}});
        // This wait is owned by the existing cancellable agent. The pinned
        // HTTP library passes negative seconds to poll as an indefinite wait.
        if(std::string(route)=="/v2/media")client.set_read_timeout(-1,0);
        client.enable_server_certificate_verification(true);
        client.enable_server_hostname_verification(true);
        client.set_follow_location(false);client.set_decompress(false);client.set_keep_alive(false);
        if(!ca.empty())client.load_ca_cert_store(ca.data(),ca.size());
        httplib::Headers headers={{"Authorization","Bearer "+credential},
            {"X-Traverse-Registration",settings.registration_id}};
        auto response=client.Post(route,headers,body.dump(),"application/json");
        if(!response)throw std::runtime_error("Observer unavailable");
        auto result=json::parse(response->body);
        if(!result.at("schemaVersion").is_number_integer() || result.at("schemaVersion")!=expected_version)
            throw std::runtime_error("Invalid observer version");
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
json finish_media(const Owner &owner,const json &probe) {
    const auto id=probe.at("id").get<std::string>();
    auto result=event("mediaFinished","notObserved");result["id"]=id;result["ended"]=false;
    const json body={{"schemaVersion",1},{"id",id}};
    if(probe.contains("receipt")) {
        result["status"]="receiptMismatch";
        try {
            auto inspected=owner.call("/media/inspect",body);
            if(inspected.first==200) {
                const auto &state=inspected.second.at("media");
                if(state.at("id")!=id || !state.at("events").is_array())throw std::runtime_error("Wrong media owner");
                std::optional<json> source;
                for(const auto &row:state.at("events"))if(row.at("type")=="received") {
                    if(source)throw std::runtime_error("Duplicate source receipt");
                    source=row;
                }
                if(source) {
                    ReadinessChallenge::Lease authority{hex(state,"instance",32),id,"",hex(*source,"nonce",64)};
                    validate_media_exchange(probe.at("receipt"),*source,authority,probe.at("mode").get<std::string>(),
                        probe.at("observerPort").get<unsigned short>(),probe.at("sourcePort").get<unsigned short>());
                    result["status"]="verified";
                }
            }
        } catch(...) {} // Invalid/missing evidence can never promote readiness.
    }
    try {
        auto ended=owner.call("/media/end",body);
        result["ended"]=ended.first==200 && ended.second.at("ok")==true;
    } catch(...) {}
    return result;
}
json check_media(const Owner &owner,const Transport &transport,const json &probe,const json &metadata,
                 unsigned short source_port,const std::string &instance,const json &evidence,
                 const std::set<std::string> &expected) {
    const auto id=hex(probe,"id",32),address=probe.at("address").get<std::string>(),mode=probe.at("mode").get<std::string>();
    const auto observer_port=metadata.at("port").get<unsigned short>();
    json cleanup={{"id",id},{"mode",mode},{"observerPort",observer_port},{"sourcePort",source_port}};
    auto result=event("mediaAddress","agentFailed");result.update({{"id",id},{"address",address},{"mode",mode},{"ended",false}});
    try {
        auto pins=addresses(metadata.at("addresses"));std::string pin;
        for(const auto &candidate:pins)
            if(mode=="relay" || (candidate.find(':')==std::string::npos)==(address.find(':')==std::string::npos)) {pin=candidate;break;}
        if(pin.empty())result["status"]="addressFamilyUnavailable";
        else {
            auto reserved=owner.call("/media/reserve",{{"schemaVersion",1},{"id",id}});
            if(reserved.first==409)result["status"]="controllerPriority";
            else {
                if(reserved.first!=200)throw std::runtime_error("Media reservation failed");
                auto authority=lease(reserved.second.at("lease"),id);
                bool loopback=address.rfind("127.",0)==0 || address=="::1";
                json config={{"schemaVersion",1},{"peer",id},{"nonce",authority.nonce},{"role","source"},
                    {"port",source_port},{"addresses",mode=="relay"?json::array({"127.0.0.1"}):
                        json(readiness_local_addresses(loopback?address:(address.find(':')==std::string::npos?"0.0.0.0":"::"),address))},
                    {"peers",json::array({{{"address",pin},{"port",observer_port}}})}};
                json body={{"schemaVersion",2},{"address",address},{"lease",reserved.second.at("lease")},
                    {"mode",mode},{"observerAddress",pin},{"observerPort",observer_port}};
                if(mode=="relay") {
                    auto prepared=owner.call("/media/relay",{{"schemaVersion",1},{"id",id},{"config",config}});
                    if(prepared.first!=202)throw std::runtime_error("Relay preparation failed");
                    body["relay"]=prepared.second.at("relay");bool ready=false;
                    while(!ready) {
                        auto state=owner.call("/media/inspect",{{"schemaVersion",1},{"id",id}});
                        if(state.first!=200)throw std::runtime_error("Relay ended");
                        for(const auto &row:state.second.at("media").at("events")) {
                            if(row.at("peer")!=id)throw std::runtime_error("Wrong relay owner");
                            if(row.at("type")=="failure" || row.at("type")=="stopped")throw std::runtime_error("Relay failed");
                            if(row.at("type")=="relayReady")ready=true;
                        }
                        if(!ready)std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    }
                } else {
                    config["advertisedAddress"]=address;
                    if(owner.call("/media/prepare",{{"schemaVersion",1},{"id",id},{"config",config}}).first!=200)
                        throw std::runtime_error("Direct preparation failed");
                }
                auto row=transport.post("/v2/media",body,2,pin);
                if(row.at("observerInstance")!=instance)throw std::runtime_error("Observer changed");
                const auto status=row.at("status").get<std::string>();
                if(status=="received") {
                    fields(row,{"schemaVersion","observerInstance","status","address","addresses","receipt","resolution"});
                    if(row.at("address")!=address || addresses(row.at("addresses"))!=expected ||
                       validate_resolution_evidence(row.at("resolution"))!=evidence)
                        throw std::runtime_error("Observer resolution changed");
                    cleanup["receipt"]=parse_media_receipt(row.at("receipt"),authority,mode,observer_port);
                } else {
                    fields(row,{"schemaVersion","observerInstance","status"});
                    static const std::set<std::string> allowed={"dnsFailed","dnsMismatch","mediaFailed","cancelled",
                        "endpointChanged","cleanupFailed","unauthorized","internalFailure"};
                    if(!allowed.count(status))throw std::runtime_error("Invalid media failure");
                    result["status"]=status;
                }
            }
        }
    } catch(...) {}
    auto finished=finish_media(owner,cleanup);result["ended"]=finished.at("ended");
    if(cleanup.contains("receipt")) {
        result["status"]=finished.at("status");
        if(result.at("status")=="verified" && result.at("ended")==true) {
            result["receipt"]=cleanup.at("receipt");result["resolution"]=evidence;
        }
    }
    if(result.at("ended")!=true)result["status"]="cleanupPending";
    return result;
}

}
void run_readiness_agent(const json &request,const std::function<void(const json &)> &emit) {
    version(request);auto operation=request.at("operation").get<std::string>();
    if(operation=="resolve") {
        if(request.contains("withMedia")) {
            fields(request,{"schemaVersion","operation","observer","withMedia"});
            if(!request.at("withMedia").is_boolean() || request.at("withMedia")!=true)
                throw std::runtime_error("Invalid media negotiation");
        } else fields(request,{"schemaVersion","operation","observer"});
        Transport transport(request.at("observer"));auto row=transport.post("/v1/resolve",{{"schemaVersion",1}});
        auto status=row.at("status").get<std::string>();auto result=event("resolved",status);
        if(status=="resolved") {
            fields(row,{"schemaVersion","observerInstance","status","addresses","resolution"});
            result["addresses"]=addresses(row.at("addresses"));
            result["resolution"]=validate_resolution_evidence(row.at("resolution"));
            if(request.contains("withMedia")) {
                result["media"]={{"status","unavailable"}};
                try {
                    auto next=transport.post("/v2/resolve",{{"schemaVersion",2}},2);
                    fields(next,{"schemaVersion","observerInstance","status","addresses","resolution","media"});
                    if(next.at("status")!="resolved" || next.at("observerInstance")!=row.at("observerInstance") ||
                       addresses(next.at("addresses"))!=addresses(row.at("addresses")) ||
                       validate_resolution_evidence(next.at("resolution"))!=result.at("resolution"))
                        throw std::runtime_error("Changed media resolution");
                    fields(next.at("media"),{"port"});const auto &port=next.at("media").at("port");
                    if(!port.is_number_integer() || port<1 || port>65535)throw std::runtime_error("Invalid observer endpoint");
                    result["media"]={{"status","available"},{"port",port},{"addresses",transport.pins()}};
                } catch(...) {} // V1 HTTPS evidence remains usable with older observers.
            }
        } else result["status"]=failure(row);
        result["observerInstance"]=row.at("observerInstance");emit(result);return;
    }
    if(operation=="check") {
        if(request.contains("media"))fields(request,{"schemaVersion","operation","observer","owner","observerInstance","probes","resolution","media"});
        else fields(request,{"schemaVersion","operation","observer","owner","observerInstance","probes","resolution"});
        auto evidence=validate_resolution_evidence(request.at("resolution"));
        Transport transport(request.at("observer"));Owner owner(request.at("owner"));
        auto instance=hex(request,"observerInstance",32);
        const auto &probes=request.at("probes");
        if(!probes.is_array() || probes.empty())throw std::runtime_error("Missing probe batch");
        if(request.contains("media")) {
            const auto &metadata=request.at("media");fields(metadata,{"sourcePort","port","addresses"});
            (void)addresses(metadata.at("addresses"));
            for(auto key:{"sourcePort","port"})
                if(!metadata.at(key).is_number_integer() || metadata.at(key)<1 || metadata.at(key)>65535)
                    throw std::runtime_error("Invalid media port");
        }
        std::set<std::string> expected,ids;
        for(const auto &probe:probes) {
            if(request.contains("media"))fields(probe,{"id","address","media"});else fields(probe,{"id","address"});
            auto id=hex(probe,"id",32);
            auto address=probe.at("address").get<std::string>();
            if(canonical_readiness_address(address)!=address || !expected.insert(address).second || !ids.insert(id).second)
                throw std::runtime_error("Duplicate or invalid probe");
            if(request.contains("media")) {
                fields(probe.at("media"),{"direct","relay"});
                for(auto mode:{"direct","relay"})if(!ids.insert(hex(probe.at("media"),mode,32)).second)
                    throw std::runtime_error("Duplicate media ID");
            }
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
                    fields(row,{"schemaVersion","observerInstance","status","address","addresses","receipt","resolution"});
                    if(row.at("address")!=probe.at("address") || addresses(row.at("addresses"))!=expected ||
                       validate_resolution_evidence(row.at("resolution"))!=evidence)
                        throw std::runtime_error("Observer address set changed");
                    (void)parse_readiness_receipt({{"schemaVersion",1},{"receipt",row.at("receipt")}},authority);
                    result["status"]="received";result["receipt"]=row.at("receipt");result["resolution"]=evidence;
                } else result["status"]=failure(row);
            } catch(...) {}
            std::lock_guard lock(writer);emit(result);
        });
        for(auto &thread:workers)thread.join();
        if(request.contains("media"))for(const auto &probe:probes)for(auto mode:{"relay","direct"}) {
            json media_probe={{"id",probe.at("media").at(mode)},{"address",probe.at("address")},{"mode",mode}};
            auto result=check_media(owner,transport,media_probe,request.at("media"),
                request.at("media").at("sourcePort").get<unsigned short>(),instance,evidence,expected);
            emit(result);
            if(result.at("ended")!=true)return; // Parent retries all known IDs before another run.
        }
        return;
    }
    if(operation=="finishMedia") {
        fields(request,{"schemaVersion","operation","owner","probes"});Owner owner(request.at("owner"));
        const auto &probes=request.at("probes");
        if(!probes.is_array())throw std::runtime_error("Invalid media cleanup batch");
        std::set<std::string> ids;
        for(const auto &probe:probes) {
            if(probe.contains("receipt"))fields(probe,{"id","mode","observerPort","sourcePort","receipt"});
            else fields(probe,{"id","mode","observerPort","sourcePort"});
            if(!ids.insert(hex(probe,"id",32)).second)throw std::runtime_error("Duplicate media cleanup ID");
            if(probe.at("mode")!="direct" && probe.at("mode")!="relay")throw std::runtime_error("Invalid media mode");
            for(auto key:{"observerPort","sourcePort"})
                if(!probe.at(key).is_number_integer() || probe.at(key)<1 || probe.at(key)>65535)
                    throw std::runtime_error("Invalid media port");
        }
        for(const auto &probe:probes)emit(finish_media(owner,probe));
        return;
    }
    if(operation=="finish") {
        if(request.contains("media"))fields(request,{"schemaVersion","operation","owner","probes","media"});
        else fields(request,{"schemaVersion","operation","owner","probes"});
        Owner owner(request.at("owner"));
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
        if(request.contains("media"))run_readiness_agent({{"schemaVersion",1},{"operation","finishMedia"},
            {"owner",request.at("owner")},{"probes",request.at("media")}},emit);
        return;
    }
    throw std::runtime_error("Unknown agent operation");
}
}
