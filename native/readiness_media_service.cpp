#include "readiness_media_service.hpp"
#include "common.hpp"
#include "readiness_challenge.hpp"
#include "readiness_media.hpp"
#include "readiness_media_transport.hpp"
#include "readiness_relay.hpp"

namespace traverse {
namespace {
void fields(const json &body,std::initializer_list<const char *> names) {
    if(!body.is_object() || body.size()!=names.size())throw std::invalid_argument("Invalid media request");
    for(auto name:names)if(!body.contains(name))throw std::invalid_argument("Invalid media request");
    if(!body.at("schemaVersion").is_number_integer() || body.at("schemaVersion")!=1)
        throw std::invalid_argument("Invalid media version");
}
std::string identifier(const json &body) {
    auto id=body.at("id").get<std::string>();
    if(!ReadinessChallenge::valid_id(id))throw std::invalid_argument("Invalid media identity");
    return id;
}
json lease_json(const ReadinessChallenge::Lease &lease) {
    return {{"instance",lease.instance},{"id",lease.id},{"token",lease.token},{"nonce",lease.nonce}};
}
void owner_reply(httplib::Response &response,json body,int status=200) {
    body.update({{"schemaVersion",1},{"pid",getpid()},{"observedMonotonicMs",
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count()}});
    reply(response,body,status);
}
}
struct ReadinessMediaService::Impl {
    struct Entry {
        ReadinessChallenge::Lease lease;
        std::optional<json> config;
        std::optional<json> relay_grant;
        bool started=false;
        std::vector<json> events;
    };
    ReadinessChallenge leases; // Separate instance/credential index from HTTPS reachability.
    ReadinessMedia source;
    const unsigned short port;
    std::mutex mutex,priority_mutex;
    bool controller=false,stopped=false;
    std::map<std::string,Entry> entries;
    std::string active;
    const bool relay_enabled;
    Impl(std::filesystem::path worker,unsigned short udp,std::string broker):source(std::move(worker),broker),port(udp),relay_enabled(!broker.empty()) {
        if(!port)throw std::invalid_argument("Media port required");
    }
    Entry *authenticate(const httplib::Request &request,const json &body) {
        auto found=entries.find(identifier(body));
        if(stopped || controller || found==entries.end())return nullptr;
        auto &lease=found->second.lease;
        if(!equal_secret(lease.token,bearer(request)) || body.at("instance")!=lease.instance ||
            body.at("nonce")!=lease.nonce)return nullptr;
        return &found->second;
    }
    bool authorized_token(const httplib::Request &request) {
        std::lock_guard lock(mutex);
        return !stopped && !controller && leases.valid_token(bearer(request));
    }
    void collect() {
        for(auto &event:source.events()) {
            auto found=entries.find(event.value("peer",std::string{}));
            if(found!=entries.end())found->second.events.push_back(std::move(event));
        }
    }
    json snapshot(Entry &entry,std::size_t cursor) {
        collect();
        if(cursor>entry.events.size())throw std::invalid_argument("Invalid media cursor");
        json events=json::array();
        for(std::size_t index=cursor;index<entry.events.size();++index)events.push_back(entry.events[index]);
        return {{"schemaVersion",1},{"instance",entry.lease.instance},{"id",entry.lease.id},
            {"started",entry.started},{"running",active==entry.lease.id && !source.idle()},
            {"cursor",entry.events.size()},{"events",std::move(events)}};
    }
    void preempt() {
        std::lock_guard priority(priority_mutex);
        {
            std::lock_guard lock(mutex);controller=true;
            for(const auto &entry:entries)leases.cancel_reserved(entry.first);
            entries.clear();active.clear();
        }
        source.preempt(); // Never hold the owner-route mutex while waiting for reap.
    }
    void owner_state(bool armed,bool paired) {
        if(!armed || paired){preempt();return;}
        std::lock_guard priority(priority_mutex);
        std::lock_guard lock(mutex);
        if(!stopped){source.owner_revoked_controller();controller=false;}
    }
    void stop() {
        {std::lock_guard lock(mutex);stopped=true;controller=true;entries.clear();active.clear();}
        source.stop();
    }
    void owner_routes(httplib::Server &server) {
        server.Post("/media/reserve",[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","id"});auto id=identifier(body);
                std::lock_guard lock(mutex);
                if(stopped || controller){owner_reply(response,{{"error","Media check unavailable"}},409);return;}
                auto lease=leases.reserve(id);
                if(!lease){owner_reply(response,{{"error","Media reservation unavailable"}},409);return;}
                entries.emplace(id,Entry{*lease,std::nullopt,std::nullopt,false,{}});
                owner_reply(response,{{"ok",true},{"lease",lease_json(*lease)}});
            } catch(const json::exception &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::invalid_argument &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){owner_reply(response,{{"error","Media unavailable"}},503);}
        });
        server.Post("/media/relay",[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","id","config"});auto id=identifier(body);
                auto config=ReadinessMediaConfig::parse(body.at("config"));
                std::lock_guard lock(mutex);auto found=entries.find(id);
                if(!relay_enabled || stopped || controller || found==entries.end()){
                    owner_reply(response,{{"error","Probe relay unavailable"}},409);return;
                }
                auto &entry=found->second;
                if(!config.source || config.relay || config.peer!=id || config.nonce!=entry.lease.nonce || config.port!=port)
                    throw std::invalid_argument("Wrong relay grant");
                if(entry.config || entry.relay_grant || entry.started){owner_reply(response,{{"error","Media grant already frozen"}},409);return;}
                auto user=random_secret(32),credential=random_secret(32),route=random_secret(32);
                if(!source.prepare_relay(id,{config.addresses,port,user,credential,route})){
                    owner_reply(response,{{"error","Probe relay unavailable"}},409);return;
                }
                entry.relay_grant=body.at("config");active=id;
                owner_reply(response,{{"ok",true},{"relay",{{"alpn",probe_relay_alpn(route)},
                    {"username",user},{"credential",credential}}}},202);
            } catch(const json::exception &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){owner_reply(response,{{"error","Invalid relay grant"}},400);}
        });
        server.Post("/media/allocations",[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","id"});auto id=identifier(body);
                {
                    std::lock_guard lock(mutex);auto found=entries.find(id);
                    if(stopped || controller || found==entries.end() || !found->second.relay_grant || found->second.started){
                        owner_reply(response,{{"error","Probe relay unavailable"}},409);return;
                    }
                }
                auto allocations=source.relay_allocations(id);
                std::lock_guard lock(mutex);auto found=entries.find(id);
                if(!allocations || stopped || controller || found==entries.end()){
                    owner_reply(response,{{"error","Probe relay unavailable"}},409);return;
                }
                json peers=json::array();
                for(const auto &peer:*allocations)peers.push_back({{"address",peer.address},{"port",peer.port}});
                owner_reply(response,{{"ok",true},{"peers",std::move(peers)}});
            } catch(const json::exception &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){owner_reply(response,{{"error","Probe relay unavailable"}},503);}
        });
        server.Post("/media/prepare",[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","id","config"});auto id=identifier(body);
                auto config=ReadinessMediaConfig::parse(body.at("config"));
                std::unique_lock lock(mutex);auto found=entries.find(id);
                if(stopped || controller || found==entries.end()){owner_reply(response,{{"error","Media lease unavailable"}},409);return;}
                auto &entry=found->second;
                if(!config.source || config.relay || config.peer!=id || config.nonce!=entry.lease.nonce || config.port!=port)
                    throw std::invalid_argument("Wrong source grant");
                if(entry.started || (entry.config && *entry.config!=body.at("config"))) {
                    owner_reply(response,{{"error","Media grant already frozen"}},409);return;
                }
                if(entry.relay_grant) {
                    auto direct=ReadinessMediaConfig::parse(*entry.relay_grant);
                    if(config.addresses!=direct.addresses || config.advertised_address!=direct.advertised_address)
                        throw std::invalid_argument("Changed relay address grant");
                    lock.unlock();auto allocations=source.relay_allocations(id);lock.lock();
                    found=entries.find(id);
                    if(!allocations || stopped || controller || found==entries.end() || found->second.started ||
                       (found->second.config && *found->second.config!=body.at("config"))){
                        owner_reply(response,{{"error","Probe relay unavailable"}},409);return;
                    }
                    for(const auto &peer:config.peers) {
                        auto contains=[&](const auto &peers) {
                            return std::any_of(peers.begin(),peers.end(),[&](const auto &allowed){return peer.address==allowed.address && peer.port==allowed.port;});
                        };
                        if(!contains(direct.peers) && !contains(*allocations))throw std::invalid_argument("Unowned relay candidate");
                    }
                }
                found->second.config=body.at("config");owner_reply(response,{{"ok",true}});
            } catch(const json::exception &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){owner_reply(response,{{"error","Invalid media grant"}},400);}
        });
        server.Post("/media/inspect",[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","id"});auto id=identifier(body);
                std::lock_guard lock(mutex);auto found=entries.find(id);
                if(found==entries.end()){owner_reply(response,{{"error","Media lease unavailable"}},404);return;}
                owner_reply(response,{{"ok",true},{"media",snapshot(found->second,0)}});
            } catch(const json::exception &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){owner_reply(response,{{"error","Media unavailable"}},503);}
        });
        server.Post("/media/end",[this](const httplib::Request &request,httplib::Response &response) {
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","id"});auto id=identifier(body);
                {
                    std::lock_guard lock(mutex);leases.cancel_reserved(id);entries.erase(id);
                    if(active==id)active.clear();
                }
                source.end(id);owner_reply(response,{{"ok",true}});
            } catch(const json::exception &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::invalid_argument &){owner_reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){owner_reply(response,{{"error","Media unavailable"}},503);}
        });
    }
    void public_routes(httplib::Server &server,const std::string &prefix) {
        server.Post(prefix+"offer",[this](const httplib::Request &request,httplib::Response &response) {
            if(!authorized_token(request)){reply(response,{{"error","Media lease unavailable"}},403);return;}
            try {
                auto body=parse_body(request);
                fields(body,{"schemaVersion","instance","id","nonce","description","candidates"});
                std::unique_lock lock(mutex);auto *entry=authenticate(request,body);
                if(!entry){reply(response,{{"error","Media lease unavailable"}},403);return;}
                if(entry->started || (!entry->config && !entry->relay_grant)){
                    reply(response,{{"error","Media offer unavailable"}},409);return;
                }
                std::optional<json> automatic;
                if(!entry->config) {
                    automatic=*entry->relay_grant;
                    auto id=entry->lease.id;
                    lock.unlock();auto allocations=source.relay_allocations(id);lock.lock();
                    entry=authenticate(request,body);
                    if(!entry){reply(response,{{"error","Media lease unavailable"}},403);return;}
                    if(entry->started){reply(response,{{"error","Media offer unavailable"}},409);return;}
                    if(!entry->config) {
                        if(!allocations || allocations->empty()){
                            reply(response,{{"error","Probe relay not ready"}},409);return;
                        }
                        // The offer cannot authorize its own destinations.
                        // Freeze only sockets owned by this lease's coturn,
                        // inspected on the persistent owner before source ICE.
                        json peers=json::array();
                        for(const auto &peer:*allocations)peers.push_back({{"address",peer.address},{"port",peer.port}});
                        (*automatic)["peers"]=std::move(peers);
                    }
                }
                const auto config=entry->config?*entry->config:*automatic;
                auto grant=ReadinessMediaConfig::parse(config);
                const auto &description=body.at("description");
                fields(description,{"schemaVersion","type","kind","sdp"});
                if(description.at("type")!="description" || description.at("kind")!="offer")
                    throw std::invalid_argument("Expected media offer");
                grant.admit_description(description.at("sdp").get<std::string>());
                if(!body.at("candidates").is_array())throw std::invalid_argument("Expected media candidates");
                for(const auto &candidate:body.at("candidates")) {
                    fields(candidate,{"schemaVersion","type","index","candidate"});
                    if(candidate.at("type")!="candidate" || !candidate.at("index").is_number_integer() ||
                        candidate.at("index").get<std::int64_t>()<0 || candidate.at("index").get<std::int64_t>()>1)
                        throw std::invalid_argument("Invalid media candidate");
                    grant.admit_candidate(candidate.at("candidate").get<std::string>());
                }
                if(!source.begin(entry->lease.id,config)){reply(response,{{"error","Media source unavailable"}},409);return;}
                entry->config=config;
                entry->started=true;active=entry->lease.id;
                source.command(active,description);
                for(const auto &candidate:body.at("candidates"))source.command(active,candidate);
                source.command(active,{{"schemaVersion",1},{"type","candidatesComplete"}});
                reply(response,snapshot(*entry,0),202);
            } catch(const json::exception &){reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){reply(response,{{"error","Invalid media offer"}},400);}
        });
        server.Post(prefix+"events",[this](const httplib::Request &request,httplib::Response &response) {
            if(!authorized_token(request)){reply(response,{{"error","Media lease unavailable"}},403);return;}
            try {
                auto body=parse_body(request);fields(body,{"schemaVersion","instance","id","nonce","cursor"});
                if(!body.at("cursor").is_number_unsigned())throw std::invalid_argument("Invalid media cursor");
                auto cursor=body.at("cursor").get<std::uint64_t>();
                std::lock_guard lock(mutex);auto *entry=authenticate(request,body);
                if(!entry){reply(response,{{"error","Media lease unavailable"}},403);return;}
                reply(response,snapshot(*entry,static_cast<std::size_t>(cursor)));
            } catch(const json::exception &){reply(response,{{"error","Invalid media request"}},400);}
              catch(const std::exception &){reply(response,{{"error","Invalid media cursor"}},400);}
        });
    }
};
ReadinessMediaService::ReadinessMediaService(std::filesystem::path worker,unsigned short port,std::string broker)
    :impl(std::make_unique<Impl>(std::move(worker),port,std::move(broker))) {}
ReadinessMediaService::~ReadinessMediaService(){impl->stop();}
void ReadinessMediaService::owner_routes(httplib::Server &server){impl->owner_routes(server);}
void ReadinessMediaService::public_routes(httplib::Server &server,const std::string &prefix){impl->public_routes(server,prefix);}
void ReadinessMediaService::preempt(){impl->preempt();}
void ReadinessMediaService::owner_state(bool armed,bool paired){impl->owner_state(armed,paired);}
void ReadinessMediaService::stop(){impl->stop();}
}
