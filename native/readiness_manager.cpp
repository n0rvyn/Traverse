#include "readiness_manager.hpp"
#include "child.hpp"
#include "readiness_verifier.hpp"
#include "name_resolution.hpp"
#include <set>

namespace traverse {
namespace {
void fields(const json &value,std::initializer_list<const char *> names) {
    if(!value.is_object() || value.size()!=names.size())throw std::runtime_error("Invalid agent event");
    for(auto name:names)if(!value.contains(name))throw std::runtime_error("Missing agent event field");
}
bool hex(const json &value,size_t count) {
    if(!value.is_string())return false;
    auto text=value.get<std::string>();
    return text.size()==count && text.find_first_not_of("0123456789abcdef")==std::string::npos;
}
bool version(const json &value) {
    return value.is_object() && value.contains("schemaVersion") && value.at("schemaVersion").is_number_integer() && value.at("schemaVersion")==1;
}
const std::set<std::string> failures={"dnsFailed","dnsMismatch","connectionFailed","tlsFailed", "httpRejected",
    "invalidReceipt","unauthorized","internalFailure","agentFailed"};
}
struct ReadinessManager::State {
    enum class Phase {Idle,Resolve,Check,Cancelling,Finish};
    ObserverSettings settings;
    std::filesystem::path agent;
    json owner;
    Phase phase=Phase::Idle;
    std::unique_ptr<OwnedOperation> worker;
    Clock::time_point started{};
    std::string status="unchecked",reason,observer_instance;
    json probes=json::array();
    json resolution=nullptr;
    std::map<std::string,json> observations,finished;
    const unsigned short media_port;
    json media_endpoint=nullptr;
    std::map<std::string,json> media_observations,media_finished;
    bool priority=false;
    size_t consumed=0;
    bool refresh=false,cleanup_pending=false,finish_protocol_failure=false;
    State(ObserverSettings value,std::filesystem::path executable,std::string socket,pid_t pid,unsigned short udp)
        :settings(std::move(value)),agent(std::move(executable)),owner({{"socket",std::move(socket)},{"pid",pid}}),media_port(udp){}
    void launch(Phase next,json request) {
        request["schemaVersion"]=1;
        consumed=0;
        worker=std::make_unique<OwnedOperation>(agent,request.dump());phase=next;
    }
    void begin() {
        if(priority){refresh=true;return;}
        started=Clock::now();status="checking";reason.clear();observer_instance.clear();
        observations.clear();finished.clear();probes=json::array();resolution=nullptr;cleanup_pending=false;
        media_observations.clear();media_finished.clear();media_endpoint=nullptr;
        auto request=json{{"operation","resolve"},{"observer",settings.agent_configuration()}};
        if(media_port)request["withMedia"]=true;
        try {launch(Phase::Resolve,std::move(request));}
        catch(...) {status="unavailable";reason="agentFailed";phase=Phase::Idle;}
    }
    void finish() {
        if(probes.empty()) {
            phase=Phase::Idle;status="unavailable";
            if(refresh && !priority){refresh=false;begin();}
            return;
        }
        json pending=json::array();
        for(const auto &probe:probes) {
            json item={{"id",probe.at("id")}};
            auto found=observations.find(probe.at("id").get<std::string>());
            if(found!=observations.end() && found->second.at("status")=="received")item["receipt"]=found->second.at("receipt");
            pending.push_back(std::move(item));
        }
        finished.clear();media_finished.clear();status="cleaning";finish_protocol_failure=false;
        json request={{"operation","finish"},{"owner",owner},{"probes",pending}};
        if(!media_endpoint.is_null()) {
            request["media"]=json::array();
            for(const auto &probe:probes)for(auto mode:{"relay","direct"})
                request["media"].push_back({{"id",probe.at("media").at(mode)},{"mode",mode},
                    {"observerPort",media_endpoint.at("port")},{"sourcePort",media_port}});
        }
        try {launch(Phase::Finish,std::move(request));}
        catch(...) {phase=Phase::Idle;status="cleanupPending";cleanup_pending=true;reason="agentFailed";}
    }
    const json &known(const json &row) const {
        auto id=row.at("id").get<std::string>();
        for(const auto &probe:probes)if(probe.at("id")==id)return probe;
        throw std::runtime_error("Unknown agent ID");
    }
    json known_media(const json &row) const {
        if(!media_endpoint.is_null())for(const auto &probe:probes)for(auto mode:{"relay","direct"})
            if(row.at("id")==probe.at("media").at(mode))return {{"id",row.at("id")},{"address",probe.at("address")},{"mode",mode}};
        throw std::runtime_error("Unknown media ID");
    }
    void accept(const json &row) {
        if(!version(row))throw std::runtime_error("Invalid event version");
        if(phase==Phase::Check && row.at("event")=="mediaAddress") {
            auto probe=known_media(row);auto id=row.at("id").get<std::string>();
            auto value=row.at("status").get<std::string>();
            if(row.at("address")!=probe.at("address") || row.at("mode")!=probe.at("mode") ||
               media_observations.count(id) || !row.at("ended").is_boolean())throw std::runtime_error("Invalid media event");
            if(value=="verified") {
                fields(row,{"schemaVersion","event","status","id","address","mode","ended","receipt","resolution"});
                const auto &receipt=row.at("receipt");
                if(row.at("ended")!=true || receipt.at("id")!=id || validate_resolution_evidence(row.at("resolution"))!=resolution)
                    throw std::runtime_error("Uncorroborated media event");
                ReadinessChallenge::Lease authority{receipt.at("instance").get<std::string>(),id,"",receipt.at("nonce").get<std::string>()};
                (void)parse_media_receipt(receipt,authority,probe.at("mode").get<std::string>(),media_endpoint.at("port").get<unsigned short>());
                if(receipt.at("media").at("transport").at("remote").at("port")!=media_port)
                    throw std::runtime_error("Wrong source media endpoint");
            } else {
                fields(row,{"schemaVersion","event","status","id","address","mode","ended"});
                static const std::set<std::string> allowed={"agentFailed","addressFamilyUnavailable","controllerPriority",
                    "dnsFailed","dnsMismatch","mediaFailed","cancelled","endpointChanged","cleanupFailed",
                    "unauthorized","internalFailure","receiptMismatch","notObserved","cleanupPending"};
                if(!allowed.count(value))throw std::runtime_error("Invalid media failure");
            }
            media_observations.emplace(id,row);return;
        }
        if(phase==Phase::Finish && row.at("event")=="mediaFinished") {
            (void)known_media(row);fields(row,{"schemaVersion","event","status","id","ended"});
            auto id=row.at("id").get<std::string>();
            if(media_finished.count(id) || !row.at("ended").is_boolean() || row.at("status")!="notObserved")
                throw std::runtime_error("Invalid media cleanup event");
            media_finished.emplace(id,row);return;
        }
        if(phase==Phase::Check) {
            const auto &probe=known(row);
            auto id=row.at("id").get<std::string>();auto result=row.at("status").get<std::string>();
            if(row.at("event")!="address" || row.at("address")!=probe.at("address") || observations.count(id))
                throw std::runtime_error("Invalid address event");
            if(result=="received") {
                fields(row,{"schemaVersion","event","id","address","status","receipt","resolution"});
                if(validate_resolution_evidence(row.at("resolution"))!=resolution)
                    throw std::runtime_error("Changed resolution evidence");
                const auto &receipt=row.at("receipt");
                fields(receipt,{"instance","id","nonce","observedMonotonicMs"});
                const auto &stamp=receipt.at("observedMonotonicMs");
                if(!hex(receipt.at("instance"),32) || receipt.at("id")!=id || !hex(receipt.at("nonce"),64) ||
                   !stamp.is_number_integer() || stamp<0 || stamp>INT64_MAX)throw std::runtime_error("Invalid event receipt");
            } else {
                fields(row,{"schemaVersion","event","id","address","status"});
                if(!failures.count(result))throw std::runtime_error("Invalid event failure");
            }
            observations.emplace(id,row);return;
        }
        if(phase==Phase::Finish) {
            (void)known(row);fields(row,{"schemaVersion","event","id","status","cancelled"});
            auto id=row.at("id").get<std::string>();auto result=row.at("status").get<std::string>();
            if(row.at("event")!="finished" || !row.at("cancelled").is_boolean() || finished.count(id) ||
               (result!="verified" && result!="notObserved" && result!="receiptMismatch" && result!="ownerUnavailable"))
                throw std::runtime_error("Invalid finishing event");
            auto observed=observations.find(id);
            if(result=="verified" && (observed==observations.end() || observed->second.at("status")!="received"))
                throw std::runtime_error("Unrequested verification");
            finished.emplace(id,row);return;
        }
        throw std::runtime_error("Unexpected agent stream");
    }
    void drain() {
        const auto &output=worker->accumulated_output();
        while(true) {
            auto end=output.find('\n',consumed);if(end==std::string::npos)break;
            auto row=json::parse(output.substr(consumed,end-consumed));consumed=end+1;accept(row);
        }
    }
    void stop(const std::string &why) {
        reason=why;status="cancelling";
        if(worker){worker->request_stop();phase=Phase::Cancelling;}
        else finish();
    }
    void complete_cleanup(bool valid) {
        cleanup_pending=!valid || finished.size()!=probes.size();
        if(!media_endpoint.is_null()) {
            if(media_finished.size()!=probes.size()*2)cleanup_pending=true;
            for(const auto &probe:probes)for(auto mode:{"relay","direct"}) {
                auto found=media_finished.find(probe.at("media").at(mode).get<std::string>());
                if(found==media_finished.end() || found->second.at("ended")!=true)cleanup_pending=true;
            }
        }
        size_t verified=0;
        for(const auto &probe:probes) {
            auto found=finished.find(probe.at("id").get<std::string>());
            if(found==finished.end() || !found->second.at("cancelled").get<bool>())cleanup_pending=true;
            else if(found->second.at("status")=="verified")++verified;
        }
        phase=Phase::Idle;
        if(cleanup_pending){status="cleanupPending";return;}
        if(!resolution.is_null() && !complete_resolution_evidence(resolution) && reason.empty())reason="dnsFailed";
        if(priority || reason=="controllerPriority")status="controllerPriority";
        else if(reason.empty() && verified==probes.size())status="verified";
        else if(verified)status="partial";
        else status="failed";
        if(refresh && !priority){refresh=false;begin();}
    }
    void tick() {
        if(!worker)return;
        if((phase==Phase::Resolve || phase==Phase::Check) && settings.timeout_ms &&
           std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-started).count()>=*settings.timeout_ms)
            stop("timeout");
        std::optional<OwnedOperation::Result> result;
        try {
            result=worker->poll();
            if(phase==Phase::Check || phase==Phase::Finish)drain();
        } catch(...) {
            if(phase==Phase::Check){observations.clear();media_observations.clear();}
            if(phase==Phase::Finish) {
                cleanup_pending=true;finish_protocol_failure=true;reason="invalidAgent";
            }
            stop("invalidAgent");return;
        }
        if(!result)return;
        auto previous=phase;
        // poll confirmed reaping and EOF; destruction cannot wait on this PID.
        worker.reset();
        if(previous==Phase::Cancelling){
            if(finish_protocol_failure)complete_cleanup(false);else finish();
            return;
        }
        if(previous==Phase::Finish) {
            complete_cleanup(result->exit_status==0 && consumed==result->output.size());return;
        }
        if(previous==Phase::Check) {
            if(result->exit_status!=0 || consumed!=result->output.size() || observations.size()!=probes.size() ||
               (!media_endpoint.is_null() && media_observations.size()!=probes.size()*2))reason="agentFailed";
            finish();return;
        }
        try {
            if(result->exit_status!=0)throw std::runtime_error("Resolver failed");
            auto row=json::parse(result->output);
            if(!version(row) || row.at("event")!="resolved" || !hex(row.at("observerInstance"),32))
                throw std::runtime_error("Invalid resolve event");
            auto resolved=row.at("status").get<std::string>();
            if(resolved!="resolved") {
                fields(row,{"schemaVersion","event","status","observerInstance"});
                if(!failures.count(resolved))throw std::runtime_error("Invalid resolver failure");
                phase=Phase::Idle;status="failed";reason=resolved;return;
            }
            if(media_port)fields(row,{"schemaVersion","event","status","observerInstance","addresses","resolution","media"});
            else fields(row,{"schemaVersion","event","status","observerInstance","addresses","resolution"});
            if(media_port) {
                const auto &media=row.at("media");
                if(media.at("status")=="available") {
                    fields(media,{"status","port","addresses"});
                    if(!media.at("port").is_number_integer() || media.at("port")<1 || media.at("port")>65535 ||
                       !media.at("addresses").is_array() || media.at("addresses").empty())throw std::runtime_error("Invalid media endpoint");
                    std::set<std::string> unique;
                    for(const auto &pin:media.at("addresses")) {
                        auto address=pin.get<std::string>();
                        if(canonical_readiness_address(address)!=address || !unique.insert(address).second)
                            throw std::runtime_error("Invalid media pin");
                    }
                    media_endpoint={{"port",media.at("port")},{"addresses",media.at("addresses")}};
                } else {fields(media,{"status"});if(media.at("status")!="unavailable")throw std::runtime_error("Invalid media negotiation");}
            }
            resolution=validate_resolution_evidence(row.at("resolution"));
            observer_instance=row.at("observerInstance").get<std::string>();
            const auto &pins=row.at("addresses");std::set<std::string> unique,identifiers;
            if(!pins.is_array() || pins.empty())throw std::runtime_error("Empty resolver result");
            for(const auto &pin:pins) {
                auto address=pin.get<std::string>();
                if(canonical_readiness_address(address)!=address || !unique.insert(address).second)
                    throw std::runtime_error("Invalid resolver pin");
                std::string id;
                do {id=random_secret(16);}while(!identifiers.insert(id).second);
                json probe={{"id",id},{"address",address}};
                if(!media_endpoint.is_null()) {
                    probe["media"]=json::object();
                    for(auto mode:{"relay","direct"}) {
                        do {id=random_secret(16);}while(!identifiers.insert(id).second);
                        probe["media"][mode]=id;
                    }
                }
                probes.push_back(std::move(probe));
            }
            json request={{"operation","check"},{"observer",settings.agent_configuration()},
                {"owner",owner},{"observerInstance",observer_instance},{"probes",probes},{"resolution",resolution}};
            if(!media_endpoint.is_null()){request["media"]=media_endpoint;request["media"]["sourcePort"]=media_port;}
            launch(Phase::Check,std::move(request));
        } catch(...) {reason="agentFailed";finish();}
    }
    json snapshot() const {
        json rows=json::array();
        for(const auto &probe:probes) {
            auto id=probe.at("id").get<std::string>();std::string value="pending";
            auto observed=observations.find(id);if(observed!=observations.end())value=observed->second.at("status").get<std::string>();
            auto done=finished.find(id);
            if(done!=finished.end() && done->second.at("cancelled")==true) {
                auto cleaned=done->second.at("status").get<std::string>();
                // Cleanup's "notObserved" must not erase the actual DNS/TLS/
                // connection failure that explains an unsuccessful URL check.
                if(cleaned!="notObserved" || observed==observations.end())value=cleaned;
            }
            else if(cleanup_pending)value="cleanupPending";
            rows.push_back({{"address",probe.at("address")},{"status",value}});
        }
        json result={{"schemaVersion",1},{"status",status},{"reason",reason},{"addresses",rows},
            {"externalReachability","unknown"},{"media","unknown"}};
        if(media_port) {
            json media_rows=json::array();size_t verified=0;
            if(!media_endpoint.is_null())for(const auto &probe:probes)for(auto mode:{"relay","direct"}) {
                auto id=probe.at("media").at(mode).get<std::string>();
                auto found=media_observations.find(id);std::string value=found==media_observations.end()?"notObserved":found->second.at("status").get<std::string>();
                if(cleanup_pending)value="cleanupPending";
                else if(phase!=Phase::Idle && found==media_observations.end())value="pending";
                if(value=="verified")++verified;
                media_rows.push_back({{"address",probe.at("address")},{"mode",mode},{"status",value}});
            }
            std::string value=priority?"activeSession":cleanup_pending?"cleanupPending":phase!=Phase::Idle?"checking":
                media_endpoint.is_null() || media_rows.empty()?"unavailable":verified==media_rows.size()?"verified":verified?"partial":"failed";
            result["media"]=value;
            result["mediaChecks"]={{"schemaVersion",1},{"status",value},{"addresses",std::move(media_rows)}};
        }
        if(!resolution.is_null())result["resolution"]=resolution;
        if(started!=Clock::time_point{})result["startedMonotonicMs"]=std::chrono::duration_cast<std::chrono::milliseconds>(started.time_since_epoch()).count();
        if(!observer_instance.empty())result["observerInstance"]=observer_instance;
        return result;
    }
};
ReadinessManager::ReadinessManager(ObserverSettings settings,std::filesystem::path agent,std::string socket,pid_t pid,unsigned short media_port)
    :state(std::make_unique<State>(std::move(settings),std::move(agent),std::move(socket),pid,media_port)){}
ReadinessManager::~ReadinessManager()=default;
bool ReadinessManager::start() {
    if(state->priority){state->refresh=true;return false;}
    if(state->worker)return false;
    if(state->cleanup_pending){state->refresh=true;state->finish();}
    else state->begin();
    return true;
}
void ReadinessManager::invalidate() {
    state->refresh=true;
    if(state->priority)return;
    if(state->worker)state->stop("invalidated");
    else if(state->cleanup_pending)state->finish();
    else {state->refresh=false;state->begin();}
}
void ReadinessManager::controller_priority(bool active) {
    if(state->priority==active)return;
    state->priority=active;state->refresh=true;
    if(active) {
        if(state->worker && state->phase!=State::Phase::Finish && state->phase!=State::Phase::Cancelling)
            state->stop("controllerPriority");
    } else if(!state->worker) {
        if(state->cleanup_pending)state->finish();
        else {state->refresh=false;state->begin();}
    }
}
void ReadinessManager::tick(){state->tick();}
nlohmann::json ReadinessManager::snapshot() const{return state->snapshot();}
}
