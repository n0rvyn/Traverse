#include "observer_media.hpp"
#include "common.hpp"
#include "readiness_media.hpp"
#include "readiness_relay.hpp"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <set>

namespace traverse {
namespace {
bool same_fields(const json &value,std::initializer_list<const char *> names) {
    if(!value.is_object() || value.size()!=names.size())return false;
    for(auto name:names)if(!value.contains(name))return false;
    return true;
}
}
struct ObserverMedia::State {
    ReadinessMedia worker;
    const std::string listen;
    std::atomic<unsigned short> port{0};
    int reservation=-1;
    std::mutex serial;
    State(std::filesystem::path executable,std::string address)
        :worker(std::move(executable),{},ReadinessMediaRole::Observer),listen(std::move(address)) {reserve(0);}
    ~State(){worker.stop();if(reservation>=0)close(reservation);}
    void reserve(unsigned short preferred) {
        auto bind_port=[&](unsigned short candidate) {
            int family=AF_INET6;
            int fd=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);
            if(fd<0){family=AF_INET;fd=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);}
            if(fd<0)return -1;
            sockaddr_storage address{};socklen_t length;
            if(family==AF_INET6) {
                int dual=0;
                if(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&dual,sizeof(dual))){close(fd);return -1;}
                auto *value=reinterpret_cast<sockaddr_in6 *>(&address);value->sin6_family=AF_INET6;value->sin6_port=htons(candidate);length=sizeof(*value);
            } else {
                auto *value=reinterpret_cast<sockaddr_in *>(&address);value->sin_family=AF_INET;value->sin_port=htons(candidate);length=sizeof(*value);
            }
            if(bind(fd,reinterpret_cast<sockaddr *>(&address),length)){close(fd);return -1;}
            if(getsockname(fd,reinterpret_cast<sockaddr *>(&address),&length)){close(fd);return -1;}
            port=ntohs(family==AF_INET6?reinterpret_cast<sockaddr_in6 *>(&address)->sin6_port:
                reinterpret_cast<sockaddr_in *>(&address)->sin_port);return fd;
        };
        reservation=bind_port(preferred);
        if(reservation<0 && preferred)reservation=bind_port(0);
        if(reservation<0){port=0;throw std::runtime_error("Observer UDP reservation unavailable");}
    }
    json run(const ReadinessVerification &request,const std::string &mode,const std::string &advertised,
             unsigned short expected_port,const json &relay,const std::function<bool()> &cancelled) {
        if(mode!="direct" && mode!="relay")throw std::invalid_argument("Invalid media mode");
        auto alias=canonical_readiness_address(advertised);
        std::unique_lock lock(serial,std::defer_lock);
        while(!lock.try_lock()) {
            if(cancelled())return {{"status","cancelled"}};
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        if(cancelled())return {{"status","cancelled"}};
        const auto selected_port=port.load();
        if(!selected_port || selected_port!=expected_port)return {{"status","endpointChanged"}};
        const auto id=random_secret(16);
        std::unique_ptr<ProbeTlsRelay> bridge;
        std::optional<json> source_received;
        json result={{"status","mediaFailed"}};
        try {
            json config={{"schemaVersion",1},{"peer",id},{"nonce",request.lease.nonce},{"role","observer"},
                {"port",selected_port},{"addresses",mode=="relay"?json::array({"127.0.0.1"}):json(readiness_local_addresses(listen,alias))},
                {"peers",json::array({{{"address",mode=="relay"?"127.0.0.1":request.target.address},{"port",request.target.port}}})}};
            if(mode=="relay") {
                if(!same_fields(relay,{"username","credential","alpn"}))throw std::invalid_argument("Invalid relay grant");
                auto alpn=relay.at("alpn").get<std::string>();
                constexpr auto prefix="traverse-probe/";
                if(alpn.rfind(prefix,0)!=0 || alpn.size()!=std::strlen(prefix)+64 ||
                   alpn.substr(std::strlen(prefix)).find_first_not_of("0123456789abcdef")!=std::string::npos)
                    throw std::invalid_argument("Invalid relay identity");
                bridge=std::make_unique<ProbeTlsRelay>(ProbeTlsEndpoint{request.target.address,request.target.host,
                    request.target.ca_file,alpn,static_cast<unsigned short>(request.target.port)});
                config["relay"]={{"port",bridge->port()},{"username",relay.at("username")},{"credential",relay.at("credential")}};
            } else {
                if(!relay.is_null())throw std::invalid_argument("Unexpected relay grant");
                config["advertisedAddress"]=alias;
            }
            (void)ReadinessMediaConfig::parse(config);
            close(reservation);reservation=-1;
            if(!worker.begin(id,config))throw std::runtime_error("Observer media unavailable");
            json description,candidates=json::array();bool gathered=false;std::optional<json> received;
            auto consume=[&](bool before_offer) {
                for(auto &event:worker.events()) {
                    if(event.at("peer")!=id)throw std::runtime_error("Wrong observer worker");
                    auto type=event.at("type").get<std::string>();
                    if(type=="failure" || type=="stopped")throw std::runtime_error("Observer media failed");
                    if(type=="description") {
                        if(!before_offer || event.at("kind")!="offer" || !description.is_null())throw std::runtime_error("Unexpected media description");
                        description={{"schemaVersion",1},{"type","description"},{"kind","offer"},{"sdp",event.at("sdp")}};
                    } else if(type=="candidate") {
                        if(!before_offer)throw std::runtime_error("Late observer candidate");
                        candidates.push_back({{"schemaVersion",1},{"type","candidate"},{"index",event.at("index")},{"candidate",event.at("candidate")}});
                    } else if(type=="gathering" && event.at("state")==2)gathered=true;
                    else if(type=="received")received=event;
                }
            };
            while(!cancelled() && (!gathered || description.is_null())) {
                consume(true);if(worker.idle())throw std::runtime_error("Observer worker exited");
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            if(cancelled())throw std::runtime_error("Observer cancelled");
            httplib::SSLClient client(request.target.host,request.target.port);
            client.set_hostname_addr_map({{request.target.host,request.target.address}});
            client.enable_server_certificate_verification(true);client.enable_server_hostname_verification(true);
            client.set_follow_location(false);client.set_keep_alive(true);client.set_decompress(false);
            if(!request.target.ca_file.empty())client.set_ca_cert_path(request.target.ca_file);
            const httplib::Headers headers={{"Origin",request.target.origin},{"Authorization","Bearer "+request.lease.token}};
            auto envelope=[&] {return json{{"schemaVersion",1},{"instance",request.lease.instance},
                {"id",request.lease.id},{"nonce",request.lease.nonce}};};
            auto offer=envelope();offer["description"]=description;offer["candidates"]=candidates;
            auto opened=client.Post(request.target.base_path+"api/readiness/media/offer",headers,offer.dump(),"application/json");
            if(!opened || opened->status!=202)throw std::runtime_error("Source media rejected");
            std::size_t cursor=0;
            while(!cancelled() && (!received || !source_received)) {
                auto body=envelope();body["cursor"]=cursor;
                auto response=client.Post(request.target.base_path+"api/readiness/media/events",headers,body.dump(),"application/json");
                if(!response || response->status!=200)throw std::runtime_error("Source media ended");
                auto row=json::parse(response->body);
                if(!same_fields(row,{"schemaVersion","instance","id","started","running","cursor","events"}) ||
                   row.at("schemaVersion")!=1 || row.at("instance")!=request.lease.instance || row.at("id")!=request.lease.id ||
                   !row.at("cursor").is_number_unsigned() || row.at("cursor").get<std::size_t>()<cursor || !row.at("events").is_array())
                    throw std::runtime_error("Invalid source media events");
                const auto next=row.at("cursor").get<std::size_t>();
                if(next-cursor!=row.at("events").size())throw std::runtime_error("Invalid source media cursor");
                cursor=next;
                for(const auto &event:row.at("events")) {
                    auto type=event.at("type").get<std::string>();
                    if(!event.at("schemaVersion").is_number_integer() || event.at("schemaVersion")!=1 || event.at("peer")!=request.lease.id)
                        throw std::runtime_error("Wrong source worker");
                    if(type=="failure" || type=="stopped")throw std::runtime_error("Source media failed");
                    if(type=="description")worker.command(id,{{"schemaVersion",1},{"type",type},{"kind",event.at("kind")},{"sdp",event.at("sdp")}});
                    else if(type=="candidate")worker.command(id,{{"schemaVersion",1},{"type",type},{"index",event.at("index")},{"candidate",event.at("candidate")}});
                    else if(type=="gathering" && event.at("state")==2)
                        worker.command(id,{{"schemaVersion",1},{"type","candidatesComplete"}});
                    else if(type=="received")source_received=validate_media_received(event,request.lease.nonce,false,request.lease.id);
                }
                consume(false);if(worker.idle())throw std::runtime_error("Observer worker exited");
                if(!received || !source_received)std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            if(!received || !source_received)throw std::runtime_error("Missing media evidence");
            (void)validate_media_received(*received,request.lease.nonce,true,id);
            const auto &local=received->at("transport").at("local");
            if((local.at("type")==3)!=(mode=="relay"))throw std::runtime_error("Wrong media path");
            result={{"status","received"},{"receipt",{{"schemaVersion",2},{"instance",request.lease.instance},
                {"id",request.lease.id},{"nonce",request.lease.nonce},{"mode",mode},{"observerPort",selected_port},
                {"observedMonotonicMs",std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count()},
                {"media",*received}}}};
        } catch(...) {if(cancelled())result={{"status","cancelled"}};}
        try {
            worker.end(id);
            if(bridge) {
                bridge->stop();auto stats=bridge->snapshot();
                if(result.at("status")=="received" && (!stats.verified || stats.failed || stats.started!=stats.finished))
                    result={{"status","mediaFailed"}};
            }
            if(result.at("status")=="received") {
                result["receipt"]["cleanup"]=true;
                result["receipt"]=parse_media_receipt(result.at("receipt"),request.lease,mode,selected_port);
                validate_media_exchange(result.at("receipt"),*source_received,request.lease,mode,selected_port,
                    static_cast<unsigned short>(request.target.port));
            }
        } catch(...) {result={{"status","cleanupFailed"}};}
        if(reservation<0)try{reserve(selected_port);}catch(...){port=0;}
        return result;
    }
};
ObserverMedia::ObserverMedia(std::filesystem::path worker,std::string address)
    :state(std::make_unique<State>(std::move(worker),std::move(address))) {}
ObserverMedia::~ObserverMedia()=default;
json ObserverMedia::endpoint() const{return {{"port",state->port.load()}};}
json ObserverMedia::check(const ReadinessVerification &request,const std::string &mode,const std::string &advertised,
    unsigned short port,const json &relay,const std::function<bool()> &cancelled) {
    return state->run(request,mode,advertised,port,relay,cancelled);
}
}
