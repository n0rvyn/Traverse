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
    size_t consumed=0;
    bool refresh=false,cleanup_pending=false,finish_protocol_failure=false;
    State(ObserverSettings value,std::filesystem::path executable,std::string socket,pid_t pid)
        :settings(std::move(value)),agent(std::move(executable)),owner({{"socket",std::move(socket)},{"pid",pid}}){}
    void launch(Phase next,json request) {
        request["schemaVersion"]=1;
        consumed=0;
        worker=std::make_unique<OwnedOperation>(agent,request.dump());phase=next;
    }
    void begin() {
        started=Clock::now();status="checking";reason.clear();observer_instance.clear();
        observations.clear();finished.clear();probes=json::array();resolution=nullptr;cleanup_pending=false;
        try {launch(Phase::Resolve,{{"operation","resolve"},{"observer",settings.agent_configuration()}});}
        catch(...) {status="unavailable";reason="agentFailed";phase=Phase::Idle;}
    }
    void finish() {
        if(probes.empty()) {
            phase=Phase::Idle;status="unavailable";
            if(refresh){refresh=false;begin();}
            return;
        }
        json pending=json::array();
        for(const auto &probe:probes) {
            json item={{"id",probe.at("id")}};
            auto found=observations.find(probe.at("id").get<std::string>());
            if(found!=observations.end() && found->second.at("status")=="received")item["receipt"]=found->second.at("receipt");
            pending.push_back(std::move(item));
        }
        finished.clear();status="cleaning";finish_protocol_failure=false;
        try {launch(Phase::Finish,{{"operation","finish"},{"owner",owner},{"probes",pending}});}
        catch(...) {phase=Phase::Idle;status="cleanupPending";cleanup_pending=true;reason="agentFailed";}
    }
    const json &known(const json &row) const {
        auto id=row.at("id").get<std::string>();
        for(const auto &probe:probes)if(probe.at("id")==id)return probe;
        throw std::runtime_error("Unknown agent ID");
    }
    void accept(const json &row) {
        if(!version(row))throw std::runtime_error("Invalid event version");
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
        size_t verified=0;
        for(const auto &probe:probes) {
            auto found=finished.find(probe.at("id").get<std::string>());
            if(found==finished.end() || !found->second.at("cancelled").get<bool>())cleanup_pending=true;
            else if(found->second.at("status")=="verified")++verified;
        }
        phase=Phase::Idle;
        if(cleanup_pending){status="cleanupPending";return;}
        if(!resolution.is_null() && !complete_resolution_evidence(resolution) && reason.empty())reason="dnsFailed";
        if(reason.empty() && verified==probes.size())status="verified";
        else if(verified)status="partial";
        else status="failed";
        if(refresh){refresh=false;begin();}
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
            if(phase==Phase::Check)observations.clear();
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
            if(result->exit_status!=0 || consumed!=result->output.size() || observations.size()!=probes.size())reason="agentFailed";
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
            fields(row,{"schemaVersion","event","status","observerInstance","addresses","resolution"});
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
                probes.push_back({{"id",id},{"address",address}});
            }
            launch(Phase::Check,{{"operation","check"},{"observer",settings.agent_configuration()},
                {"owner",owner},{"observerInstance",observer_instance},{"probes",probes},{"resolution",resolution}});
        } catch(...) {reason="agentFailed";finish();}
    }
    json snapshot() const {
        json rows=json::array();
        for(const auto &probe:probes) {
            auto id=probe.at("id").get<std::string>();std::string value="pending";
            auto observed=observations.find(id);if(observed!=observations.end())value=observed->second.at("status").get<std::string>();
            auto done=finished.find(id);
            if(done!=finished.end() && done->second.at("cancelled")==true)value=done->second.at("status").get<std::string>();
            else if(cleanup_pending)value="cleanupPending";
            rows.push_back({{"address",probe.at("address")},{"status",value}});
        }
        json result={{"schemaVersion",1},{"status",status},{"reason",reason},{"addresses",rows},
            {"externalReachability","unknown"},{"media","unknown"}};
        if(!resolution.is_null())result["resolution"]=resolution;
        if(started!=Clock::time_point{})result["startedMonotonicMs"]=std::chrono::duration_cast<std::chrono::milliseconds>(started.time_since_epoch()).count();
        if(!observer_instance.empty())result["observerInstance"]=observer_instance;
        return result;
    }
};
ReadinessManager::ReadinessManager(ObserverSettings settings,std::filesystem::path agent,std::string socket,pid_t pid)
    :state(std::make_unique<State>(std::move(settings),std::move(agent),std::move(socket),pid)){}
ReadinessManager::~ReadinessManager()=default;
bool ReadinessManager::start() {
    if(state->worker)return false;
    if(state->cleanup_pending){state->refresh=true;state->finish();}
    else state->begin();
    return true;
}
void ReadinessManager::invalidate() {
    state->refresh=true;
    if(state->worker)state->stop("invalidated");
    else if(state->cleanup_pending)state->finish();
    else {state->refresh=false;state->begin();}
}
void ReadinessManager::tick(){state->tick();}
nlohmann::json ReadinessManager::snapshot() const{return state->snapshot();}
}
