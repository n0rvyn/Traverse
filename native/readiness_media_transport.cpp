#define GST_USE_UNSTABLE_API
#include "readiness_media_transport.hpp"
#include <agent.h>
#include <arpa/inet.h>
#include <gst/app/gstappsink.h>
#include <gst/sdp/sdp.h>
#include <gst/webrtc/webrtc.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <climits>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>

namespace traverse {
namespace {
using json=nlohmann::json;
[[noreturn]] void invalid(){throw std::invalid_argument("Invalid private media protocol");}
bool hex(const std::string &value,std::size_t size){return value.size()==size && value.find_first_not_of("0123456789abcdef")==std::string::npos;}
void fields(const json &value,std::initializer_list<const char *> required,std::initializer_list<const char *> optional={}) {
    if(!value.is_object())invalid();
    for(auto field:required)if(!value.contains(field))invalid();
    for(auto it=value.begin();it!=value.end();++it) {
        auto matches=[&](const char *field){return it.key()==field;};
        if(std::none_of(required.begin(),required.end(),matches) && std::none_of(optional.begin(),optional.end(),matches))invalid();
    }
}
unsigned number(const std::string &value) {
    unsigned result=0;auto end=value.data()+value.size();auto parsed=std::from_chars(value.data(),end,result);
    if(value.empty() || parsed.ec!=std::errc{} || parsed.ptr!=end || !result || result>65535)invalid();
    return result;
}
std::uint16_t parse_port(const json &value){if(!value.is_number_integer())invalid();auto n=value.get<std::int64_t>();if(n<1 || n>65535)invalid();return n;}
std::string numeric(const std::string &value,bool placeholder=false) {
    if(value.find('\0')!=std::string::npos)invalid();
    in_addr v4{};in6_addr v6{};std::array<char,INET6_ADDRSTRLEN> text{};
    if(inet_pton(AF_INET,value.c_str(),&v4)==1) {
        auto bits=ntohl(v4.s_addr);
        if((!bits && !placeholder) || bits==0xffffffffu || (bits&0xf0000000u)==0xe0000000u)invalid();
        if(!inet_ntop(AF_INET,&v4,text.data(),text.size()))invalid();
    } else if(inet_pton(AF_INET6,value.c_str(),&v6)==1) {
        if(IN6_IS_ADDR_V4MAPPED(&v6)) {
            if(!inet_ntop(AF_INET,v6.s6_addr+12,text.data(),text.size()))invalid();
            return numeric(text.data(),placeholder);
        }
        if((IN6_IS_ADDR_UNSPECIFIED(&v6) && !placeholder) || IN6_IS_ADDR_MULTICAST(&v6))invalid();
        if(!inet_ntop(AF_INET6,&v6,text.data(),text.size()))invalid();
    } else invalid();
    return text.data();
}
std::vector<std::string> words(const std::string &value) {
    if(value.find_first_of("\r\n")!=std::string::npos || value.find('\0')!=std::string::npos)invalid();
    std::istringstream input(value);std::vector<std::string> result;std::string item;
    while(input>>item)result.push_back(item);
    return result;
}
bool granted(const ReadinessMediaConfig &config,const std::string &address,unsigned port) {
    return std::any_of(config.peers.begin(),config.peers.end(),[&](const auto &peer){return peer.address==address && peer.port==port;});
}
std::string advertise_candidate(const std::string &text,const ReadinessMediaConfig &config) {
    if(!config.advertised_address || text.empty())return text;
    auto parts=words(text);
    if(parts.size()<8 || parts[0].rfind("candidate:",0)!=0 || parts[1]!="1" ||
       (parts[2]!="UDP" && parts[2]!="udp") || parts[6]!="typ" || parts[7]!="host" ||
       number(parts[5])!=config.port)invalid();
    auto address=numeric(parts[4]);
    if(std::find(config.addresses.begin(),config.addresses.end(),address)==config.addresses.end())invalid();
    parts[4]=*config.advertised_address;
    std::string result;
    for(const auto &part:parts){if(!result.empty())result+=' ';result+=part;}
    return result;
}
std::string advertise_description(const std::string &text,const ReadinessMediaConfig &config) {
    if(!config.advertised_address)return text;
    std::istringstream input(text);std::string line,result;
    while(std::getline(input,line)) {
        if(!line.empty() && line.back()=='\r')line.pop_back();
        if(line.rfind("a=candidate:",0)==0)line="a="+advertise_candidate(line.substr(2),config);
        else if(line.rfind("c=IN ",0)==0) {
            auto parts=words(line);
            if(parts.size()!=3 || (parts[1]!="IP4" && parts[1]!="IP6"))invalid();
            auto address=numeric(parts[2],true);
            if(address!="0.0.0.0" && address!="::") {
                if(std::find(config.addresses.begin(),config.addresses.end(),address)==config.addresses.end())invalid();
                line="c=IN "+std::string(config.advertised_address->find(':')==std::string::npos?"IP4 ":"IP6 ")+*config.advertised_address;
            }
        }
        result+=line+"\r\n";
    }
    return result;
}
void connection(const GstSDPConnection *value,const ReadinessMediaConfig &config) {
    if(!value || !value->address)return;
    auto address=numeric(value->address,true);
    if(address!="0.0.0.0" && address!="::" && std::none_of(config.peers.begin(),config.peers.end(),[&](const auto &peer){return peer.address==address;}))invalid();
}
}
ReadinessMediaConfig ReadinessMediaConfig::parse(const json &value) {
    fields(value,{"schemaVersion","peer","nonce","role","port","addresses","peers"},{"relay","advertisedAddress"});
    if(value.at("schemaVersion")!=1 || !value.at("schemaVersion").is_number_integer())invalid();
    ReadinessMediaConfig result;
    result.peer=value.at("peer").get<std::string>();result.nonce=value.at("nonce").get<std::string>();
    if(!hex(result.peer,32) || !hex(result.nonce,64))invalid();
    auto role=value.at("role").get<std::string>();if(role!="source" && role!="observer")invalid();result.source=role=="source";
    result.port=parse_port(value.at("port"));
    if(!value.at("addresses").is_array() || value.at("addresses").empty() || !value.at("peers").is_array() || value.at("peers").empty())invalid();
    std::set<std::string> local;
    for(const auto &item:value.at("addresses")){auto address=numeric(item.get<std::string>());if(!local.insert(address).second)invalid();result.addresses.push_back(address);}
    std::set<std::pair<std::string,unsigned>> remote;
    for(const auto &item:value.at("peers")) {
        fields(item,{"address","port"});ReadinessMediaPeer peer{numeric(item.at("address").get<std::string>()),parse_port(item.at("port"))};
        if(!remote.emplace(peer.address,peer.port).second)invalid();
        result.peers.push_back(std::move(peer));
    }
    if(value.contains("relay")) {
        if(result.source)invalid();
        const auto &relay=value.at("relay");fields(relay,{"port","username","credential"});
        ReadinessMediaRelay target{parse_port(relay.at("port")),relay.at("username"),relay.at("credential")};
        if(!hex(target.username,64) || !hex(target.credential,64))invalid();
        result.relay=std::move(target);
    }
    if(value.contains("advertisedAddress")) {
        if(result.relay)invalid();
        auto address=numeric(value.at("advertisedAddress").get<std::string>());
        for(const auto &local:result.addresses)
            if((local.find(':')==std::string::npos)!=(address.find(':')==std::string::npos))invalid();
        result.advertised_address=std::move(address);
    }
    return result;
}
std::string ReadinessMediaConfig::admit_candidate(const std::string &candidate) const {
    // GStreamer emits the empty end-of-candidates marker. It names no peer.
    if(candidate.empty())return {};
    auto parts=words(candidate);
    if(parts.size()<8 || parts[0].rfind("candidate:",0)!=0 || parts[0].size()==10 || parts[1]!="1" ||
        (parts[2]!="UDP" && parts[2]!="udp") || parts[6]!="typ" ||
        (parts[7]!="host" && parts[7]!="srflx" && parts[7]!="prflx" && parts[7]!="relay"))invalid();
    parts[4]=numeric(parts[4]);auto target=number(parts[5]);if(!granted(*this,parts[4],target))invalid();
    parts[5]=std::to_string(target);
    for(std::size_t i=8;i<parts.size();i+=2) {
        if(i+1==parts.size())invalid();
        if(parts[i]=="raddr")parts[i+1]=numeric(parts[i+1],true);
        if(parts[i]=="rport" && parts[i+1]!="0")number(parts[i+1]);
    }
    std::string result;for(const auto &part:parts){if(!result.empty())result+=' ';result+=part;}return result;
}
std::string ReadinessMediaConfig::admit_description(const std::string &text) const {
    if(text.find('\0')!=std::string::npos || text.size()>G_MAXUINT)invalid();
    std::istringstream lines(text);std::string line,canonical;
    while(std::getline(lines,line)) {
        if(!line.empty() && line.back()=='\r')line.pop_back();
        if(line.rfind("a=candidate:",0)==0)line="a="+admit_candidate(line.substr(2));
        canonical+=line+"\r\n";
    }
    GstSDPMessage *raw=nullptr;if(gst_sdp_message_new(&raw)!=GST_SDP_OK)invalid();
    std::unique_ptr<GstSDPMessage,decltype(&gst_sdp_message_free)> sdp(raw,gst_sdp_message_free);
    if(gst_sdp_message_parse_buffer(reinterpret_cast<const guint8 *>(canonical.data()),canonical.size(),sdp.get())!=GST_SDP_OK)invalid();
    auto check_attribute=[&](const GstSDPAttribute *attribute) {
        const std::string key=attribute->key?attribute->key:"";
        if(key=="remote-candidates") {
            auto values=words(attribute->value?attribute->value:"");if(values.empty() || values.size()%3)invalid();
            for(std::size_t n=0;n<values.size();n+=3)if(values[n]!="1" || !granted(*this,numeric(values[n+1]),number(values[n+2])))invalid();
        }
        if(key=="rtcp") {
            auto values=words(attribute->value?attribute->value:"");
            if(values.size()!=1 && values.size()!=4)invalid();
            number(values[0]);if(values.size()==4)numeric(values[3],true);
        }
    };
    const auto *origin=gst_sdp_message_get_origin(sdp.get());
    if(origin && origin->addr && *origin->addr)numeric(origin->addr,true);
    connection(gst_sdp_message_get_connection(sdp.get()),*this);
    for(unsigned a=0;a<gst_sdp_message_attributes_len(sdp.get());++a)check_attribute(gst_sdp_message_get_attribute(sdp.get(),a));
    unsigned video=0,data=0;std::vector<std::string> mids;
    for(unsigned i=0;i<gst_sdp_message_medias_len(sdp.get());++i) {
        auto *media=gst_sdp_message_get_media(sdp.get(),i);std::string kind=gst_sdp_media_get_media(media)?gst_sdp_media_get_media(media):"";
        const std::string protocol=gst_sdp_media_get_proto(media)?gst_sdp_media_get_proto(media):"";
        if(kind=="video") {
            if(i!=0 || protocol!="UDP/TLS/RTP/SAVPF")invalid();
            ++video;const std::string wanted=source?"recvonly":"sendonly";unsigned directions=0;bool direction_ok=false,mux=false;
            for(unsigned a=0;a<gst_sdp_media_attributes_len(media);++a) {
                const auto *attribute=gst_sdp_media_get_attribute(media,a);const std::string key=attribute->key?attribute->key:"";
                if(key=="recvonly" || key=="sendonly" || key=="sendrecv" || key=="inactive"){++directions;if(key==wanted)direction_ok=true;}
                if(key=="rtcp-mux")mux=true;
            }
            if(directions!=1 || !direction_ok || !mux)invalid();
        } else if(kind=="application") {
            if(i!=1 || protocol!="UDP/DTLS/SCTP")invalid();
            ++data;
        } else invalid();
        auto *mid=gst_sdp_media_get_attribute_val(media,"mid");if(!mid || !*mid || words(mid).size()!=1)invalid();mids.emplace_back(mid);
        for(unsigned c=0;c<gst_sdp_media_connections_len(media);++c)connection(gst_sdp_media_get_connection(media,c),*this);
        for(unsigned a=0;a<gst_sdp_media_attributes_len(media);++a)check_attribute(gst_sdp_media_get_attribute(media,a));
    }
    auto *group=gst_sdp_message_get_attribute_val(sdp.get(),"group");if(!group)invalid();auto bundle=words(group);
    if(mids.size()!=2 || mids[0]==mids[1] || bundle.size()!=3 || bundle[0]!="BUNDLE" || bundle[1]!=mids[0] || bundle[2]!=mids[1])invalid();
    if(video!=1 || data!=1)invalid();
    return canonical;
}

struct ReadinessMediaTransport::State : std::enable_shared_from_this<State> {
    ReadinessMediaConfig config;
    GstElement *pipeline=nullptr,*rtc=nullptr;
    NiceAgent *agent=nullptr;
    GstBus *bus=nullptr;
    std::mutex objects,queue_mutex,promise_mutex,candidate_mutex;
    std::deque<json> queued;
    std::set<GstPromise *> promises;
    std::vector<std::pair<unsigned,std::string>> candidates;
    std::atomic<bool> stopped{false},failure{false},offer_needed{false},decoded{false},data_verified{false},remote_ready{false},reported{false};
    bool offered=false,remote_submitted=false;
    explicit State(ReadinessMediaConfig value):config(std::move(value)){}
    ~State(){stop();}
    void emit(json value) {
        if(stopped)return;
        if(value.value("type",std::string{})=="candidate")value["candidate"]=advertise_candidate(value.at("candidate"),config);
        else if(value.value("type",std::string{})=="description")value["sdp"]=advertise_description(value.at("sdp"),config);
        value["schemaVersion"]=1;value["peer"]=config.peer;value["port"]=config.port;
        std::lock_guard lock(queue_mutex);queued.push_back(std::move(value));
    }
    void fail(const char *reason) noexcept {
        if(failure.exchange(true) || stopped)return;
        try{emit({{"type","failure"},{"reason",reason}});}catch(...){}
    }
    template<class F> void safe(F action) noexcept {try{if(!stopped)action();}catch(...){fail("internalFailure");}}
    static void release(gpointer data,GClosure*){delete static_cast<std::shared_ptr<State> *>(data);}
    void signal(gpointer object,const char *name,GCallback callback) {
        g_signal_connect_data(object,name,callback,new std::shared_ptr<State>(shared_from_this()),release,GConnectFlags(0));
    }
    static State &self(gpointer data){return **static_cast<std::shared_ptr<State> *>(data);}
    GstElement *rtc_ref() {
        std::lock_guard lock(objects);return stopped || !rtc ? nullptr : GST_ELEMENT(gst_object_ref(rtc));
    }
    struct Pending {std::shared_ptr<State> owner;std::string purpose,kind,text;};
    void promise(const char *action,const char *purpose,GstWebRTCSessionDescription *description=nullptr,std::string kind={},std::string text={}) {
        std::unique_ptr<GstElement,decltype(&gst_object_unref)> target(rtc_ref(),gst_object_unref);if(!target)return;
        auto *payload=new Pending{shared_from_this(),purpose,std::move(kind),std::move(text)};
        auto *p=gst_promise_new_with_change_func(+[](GstPromise *p,gpointer data){
            auto &pending=*static_cast<Pending *>(data);auto owner=pending.owner;
            owner->safe([&]{
                if(gst_promise_wait(p)!=GST_PROMISE_RESULT_REPLIED){owner->fail("descriptionFailed");return;}
                auto *reply=gst_promise_get_reply(p);
                if(reply && gst_structure_has_field(reply,"error")){owner->fail("descriptionFailed");return;}
                if(pending.purpose=="create") {
                    GstWebRTCSessionDescription *description=nullptr;
                    if(!reply || !gst_structure_get(reply,pending.kind.c_str(),GST_TYPE_WEBRTC_SESSION_DESCRIPTION,&description,nullptr) || !description){owner->fail("descriptionFailed");return;}
                    gchar *text=gst_sdp_message_as_text(description->sdp);
                    owner->promise("set-local-description","local",description,pending.kind,text?text:"");
                    g_free(text);gst_webrtc_session_description_free(description);
                } else if(pending.purpose=="local") owner->emit({{"type","description"},{"kind",pending.kind},{"sdp",pending.text}});
                else {
                    owner->remote_ready=true;owner->flush_candidates();
                    if(owner->config.source)owner->create_description();
                }
            });
            {std::lock_guard lock(owner->promise_mutex);owner->promises.erase(p);}
            gst_promise_unref(p);
        },payload,+[](gpointer data){delete static_cast<Pending *>(data);});
        gst_promise_ref(p);
        {
            std::lock_guard lock(promise_mutex);
            if(stopped){gst_promise_unref(p);gst_promise_unref(p);return;}
            promises.insert(p);
        }
        if(description)g_signal_emit_by_name(target.get(),action,description,p);
        else g_signal_emit_by_name(target.get(),action,nullptr,p);
        gst_promise_unref(p);
    }
    void create_description(){promise(config.source?"create-answer":"create-offer","create",nullptr,config.source?"answer":"offer");}
    std::mutex candidate_flush_mutex;
    bool candidates_complete=false,completion_forwarded=false;
    void flush_candidates() {
        std::lock_guard serial(candidate_flush_mutex);
        std::vector<std::pair<unsigned,std::string>> pending;
        bool complete=false;
        {std::lock_guard lock(candidate_mutex);if(!remote_ready)return;pending.swap(candidates);
            complete=candidates_complete && !completion_forwarded;completion_forwarded|=complete;}
        std::unique_ptr<GstElement,decltype(&gst_object_unref)> target(rtc_ref(),gst_object_unref);if(!target)return;
        for(const auto &candidate:pending)g_signal_emit_by_name(target.get(),"add-ice-candidate",candidate.first,candidate.second.c_str());
        // Pinned GStreamer forwards NULL to libnice's supported
        // peer_candidate_gathering_done call. Without it trickle ICE keeps
        // waiting for more candidates after its connectivity checks exhaust.
        if(complete)g_signal_emit_by_name(target.get(),"add-ice-candidate",0,static_cast<const gchar *>(nullptr));
    }
    void channel(GstWebRTCDataChannel *channel) {
        gchar *label=nullptr;g_object_get(channel,"label",&label,nullptr);bool accepted=label && std::string(label)=="readiness";g_free(label);
        if(!accepted){gst_webrtc_data_channel_close(channel);fail("unexpectedChannel");return;}
        signal(channel,"on-open",G_CALLBACK((+[](GstWebRTCDataChannel *channel,gpointer data){
            auto &s=self(data);s.safe([&]{
                if(s.config.source){GError *error=nullptr;if(!gst_webrtc_data_channel_send_string_full(channel,s.config.nonce.c_str(),&error))s.fail("dataFailed");if(error)g_error_free(error);}
            });
        })));
        signal(channel,"on-message-string",G_CALLBACK((+[](GstWebRTCDataChannel *channel,gchar *message,gpointer data){
            auto &s=self(data);s.safe([&]{
                const std::string text=message?message:"";
                if(s.config.source){if(text!="echo:"+s.config.nonce){s.fail("nonceRejected");return;}}
                else {
                    if(text!=s.config.nonce){s.fail("nonceRejected");return;}
                    GError *error=nullptr;auto echo="echo:"+s.config.nonce;
                    if(!gst_webrtc_data_channel_send_string_full(channel,echo.c_str(),&error))s.fail("dataFailed");if(error)g_error_free(error);
                }
                if(!s.data_verified.exchange(true))s.emit({{"type","dataVerified"},{"nonce",s.config.nonce}});
            });
        })));
    }
    void build() {
        GError *error=nullptr;
        if(config.source) {
            pipeline=gst_parse_launch("videotestsrc is-live=true ! video/x-raw,width=160,height=120,framerate=15/1 ! videoconvert ! vp8enc deadline=1 cpu-used=8 threads=1 keyframe-max-dist=15 ! rtpvp8pay pt=96 ! application/x-rtp,media=video,encoding-name=VP8,payload=96 ! webrtcbin name=rtc bundle-policy=max-bundle",&error);
            if(error){g_error_free(error);throw std::runtime_error("Cannot build synthetic media source");}
            if(pipeline)rtc=gst_bin_get_by_name(GST_BIN(pipeline),"rtc");
        } else {
            pipeline=gst_pipeline_new(nullptr);rtc=gst_element_factory_make("webrtcbin","rtc");
            if(pipeline && rtc){g_object_set(rtc,"bundle-policy",GST_WEBRTC_BUNDLE_POLICY_MAX_BUNDLE,nullptr);gst_bin_add(GST_BIN(pipeline),rtc);gst_object_ref(rtc);}
        }
        if(!pipeline || !rtc)throw std::runtime_error("Synthetic media factories unavailable");
        GstWebRTCICE *ice=nullptr;g_object_get(rtc,"ice-agent",&ice,nullptr);if(!ice)throw std::runtime_error("Missing native ICE");
        g_object_set(ice,"min-rtp-port",unsigned(config.port),"max-rtp-port",unsigned(config.port),"ice-tcp",FALSE,nullptr);
        g_object_get(ice,"agent",&agent,nullptr);g_object_unref(ice);if(!agent)throw std::runtime_error("Missing native ICE agent");
        std::vector<std::string> tuples;for(const auto &peer:config.peers)tuples.push_back(peer.address+"|"+std::to_string(peer.port));
        std::vector<const gchar *> allowlist;for(const auto &tuple:tuples)allowlist.push_back(tuple.c_str());allowlist.push_back(nullptr);
        g_object_set(agent,"probe-peer-allowlist",allowlist.data(),nullptr);
        gchar **readback=nullptr;g_object_get(agent,"probe-peer-allowlist",&readback,nullptr);
        bool admitted=readback && g_strv_length(readback)==tuples.size();
        if(admitted)for(std::size_t i=0;i<tuples.size();++i)if(tuples[i]!=readback[i])admitted=false;
        g_strfreev(readback);if(!admitted)throw std::runtime_error("Native probe peer policy unavailable");
        for(const auto &ip:config.addresses){NiceAddress address;nice_address_init(&address);if(!nice_address_set_from_string(&address,ip.c_str()) || !nice_agent_add_local_address(agent,&address))invalid();}
        // No implicit public discovery endpoint. Direct checks use admitted
        // endpoints; relay discovery is restricted to the owned local bridge.
        g_object_set(rtc,"stun-server",nullptr,nullptr);
        if(config.relay) {
            // Set the native policy before any stream exists. Relay-scoped
            // peer identities must never fall back to a local UDP candidate.
            g_object_set(agent,"force-relay",TRUE,nullptr);
            gboolean forced=FALSE;g_object_get(agent,"force-relay",&forced,nullptr);
            if(!forced)throw std::runtime_error("Native relay-only policy unavailable");
            const auto &relay=*config.relay;auto uri="turn://"+relay.username+":"+relay.credential+"@127.0.0.1:"+std::to_string(relay.port)+"?transport=tcp";
            g_object_set(rtc,"turn-server",uri.c_str(),"ice-transport-policy",GST_WEBRTC_ICE_TRANSPORT_POLICY_RELAY,nullptr);
        }
        signal(rtc,"on-negotiation-needed",G_CALLBACK((+[](GstElement*,gpointer data){self(data).offer_needed=true;})));
        signal(rtc,"on-ice-candidate",G_CALLBACK((+[](GstElement*,guint index,gchar *candidate,gpointer data){auto &s=self(data);s.safe([&]{s.emit({{"type","candidate"},{"index",index},{"candidate",candidate?candidate:""}});});})));
        signal(rtc,"notify::ice-gathering-state",G_CALLBACK((+[](GObject *object,GParamSpec*,gpointer data){auto &s=self(data);s.safe([&]{GstWebRTCICEGatheringState value;g_object_get(object,"ice-gathering-state",&value,nullptr);s.emit({{"type","gathering"},{"state",int(value)}});});})));
        signal(rtc,"notify::ice-connection-state",G_CALLBACK((+[](GObject *object,GParamSpec*,gpointer data){auto &s=self(data);s.safe([&]{GstWebRTCICEConnectionState value;g_object_get(object,"ice-connection-state",&value,nullptr);if(value==GST_WEBRTC_ICE_CONNECTION_STATE_FAILED)s.fail("connectionFailed");});})));
        signal(rtc,"notify::connection-state",G_CALLBACK((+[](GObject *object,GParamSpec*,gpointer data){auto &s=self(data);s.safe([&]{GstWebRTCPeerConnectionState value;g_object_get(object,"connection-state",&value,nullptr);if(value==GST_WEBRTC_PEER_CONNECTION_STATE_FAILED)s.fail("connectionFailed");});})));
        signal(rtc,"on-data-channel",G_CALLBACK((+[](GstElement*,GstWebRTCDataChannel *channel,gpointer data){auto &s=self(data);s.safe([&]{s.channel(channel);});})));
        signal(rtc,"pad-added",G_CALLBACK((+[](GstElement*,GstPad *pad,gpointer data){auto &s=self(data);s.safe([&]{s.pad(pad);});})));
        if(!config.source) {
            auto *caps=gst_caps_from_string("application/x-rtp,media=video,encoding-name=VP8,payload=(int)96,clock-rate=(int)90000");GstWebRTCRTPTransceiver *transceiver=nullptr;
            g_signal_emit_by_name(rtc,"add-transceiver",GST_WEBRTC_RTP_TRANSCEIVER_DIRECTION_RECVONLY,caps,&transceiver);gst_caps_unref(caps);
            if(!transceiver)throw std::runtime_error("Cannot create probe video receiver");
            gst_object_unref(transceiver);
        }
        bus=gst_element_get_bus(pipeline);
        if(gst_element_set_state(pipeline,GST_STATE_PLAYING)==GST_STATE_CHANGE_FAILURE)throw std::runtime_error("Cannot start synthetic media");
        if(!config.source){GstWebRTCDataChannel *data=nullptr;g_signal_emit_by_name(rtc,"create-data-channel","readiness",nullptr,&data);if(!data)throw std::runtime_error("Cannot create probe data channel");channel(data);g_object_unref(data);}
        emit({{"type","ready"}});
    }
    void pad(GstPad *pad) {
        if(GST_PAD_DIRECTION(pad)!=GST_PAD_SRC)return;
        if(config.source){fail("unexpectedMedia");return;}
        GError *error=nullptr;auto *decoder=gst_parse_bin_from_description("queue ! rtpvp8depay ! vp8dec ! videoconvert ! video/x-raw,format=RGB ! appsink name=decoded emit-signals=true sync=false",TRUE,&error);
        if(error || !decoder){if(error)g_error_free(error);fail("decodeFailed");return;}
        auto *sink=gst_bin_get_by_name(GST_BIN(decoder),"decoded");
        signal(sink,"new-sample",G_CALLBACK((+[](GstAppSink *sink,gpointer data)->GstFlowReturn {
            auto &s=self(data);GstFlowReturn result=GST_FLOW_OK;
            s.safe([&]{auto *sample=gst_app_sink_pull_sample(sink);if(!sample){result=GST_FLOW_ERROR;return;}
                auto *buffer=gst_sample_get_buffer(sample);auto *caps=gst_sample_get_caps(sample);int width=0,height=0;
                bool valid=buffer && gst_buffer_get_size(buffer)>0 && caps && gst_structure_get_int(gst_caps_get_structure(caps,0),"width",&width) && gst_structure_get_int(gst_caps_get_structure(caps,0),"height",&height) && width==160 && height==120;
                if(valid){if(!s.decoded.exchange(true))s.emit({{"type","decoded"},{"width",width},{"height",height},{"bytes",gst_buffer_get_size(buffer)}});}
                else{s.fail("decodeFailed");result=GST_FLOW_ERROR;}gst_sample_unref(sample);
            });return result;
        })));
        gst_object_unref(sink);
        GstElement *owner=nullptr;{std::lock_guard lock(objects);if(!stopped && pipeline)owner=GST_ELEMENT(gst_object_ref(pipeline));}
        if(!owner){gst_object_unref(decoder);return;}
        gst_bin_add(GST_BIN(owner),decoder);auto *input=gst_element_get_static_pad(decoder,"sink");
        if(gst_pad_link(pad,input)!=GST_PAD_LINK_OK)fail("decodeFailed");
        gst_object_unref(input);gst_element_sync_state_with_parent(decoder);gst_object_unref(owner);
    }
    void command(const json &value) {
        if(value.at("type")=="description") {
            fields(value,{"schemaVersion","type","kind","sdp"});if(remote_submitted || value.at("kind")!=(config.source?"offer":"answer"))invalid();
            auto text=config.admit_description(value.at("sdp"));GstSDPMessage *sdp=nullptr;gst_sdp_message_new(&sdp);
            if(gst_sdp_message_parse_buffer(reinterpret_cast<const guint8 *>(text.data()),text.size(),sdp)!=GST_SDP_OK){gst_sdp_message_free(sdp);invalid();}
            auto *description=gst_webrtc_session_description_new(config.source?GST_WEBRTC_SDP_TYPE_OFFER:GST_WEBRTC_SDP_TYPE_ANSWER,sdp);
            remote_submitted=true;promise("set-remote-description","remote",description);gst_webrtc_session_description_free(description);
        } else if(value.at("type")=="candidate") {
            fields(value,{"schemaVersion","type","index","candidate"});if(!value.at("index").is_number_unsigned() && !value.at("index").is_number_integer())invalid();
            auto index=value.at("index").get<std::int64_t>();if(index<0 || index>1)invalid();
            auto candidate=config.admit_candidate(value.at("candidate"));{std::lock_guard lock(candidate_mutex);if(candidates_complete)invalid();candidates.emplace_back(index,std::move(candidate));}flush_candidates();
        } else if(value.at("type")=="candidatesComplete") {
            fields(value,{"schemaVersion","type"});
            {std::lock_guard lock(candidate_mutex);if(candidates_complete)invalid();candidates_complete=true;}
            flush_candidates();
        } else invalid();
    }
    void receipt() {
        if(reported || !data_verified || (!config.source && !decoded))return;
        std::lock_guard lock(objects);if(stopped || !agent || !rtc)return;
        GstWebRTCPeerConnectionState connection;g_object_get(rtc,"connection-state",&connection,nullptr);if(connection!=GST_WEBRTC_PEER_CONNECTION_STATE_CONNECTED)return;
        NiceCandidate *local=nullptr,*remote=nullptr;
        // One isolated webrtcbin and one BUNDLE transport; its first Nice stream.
        if(!nice_agent_get_selected_pair(agent,1,1,&local,&remote) || !local || !remote)return;
        auto candidate=[](NiceCandidate *value){std::array<char,INET6_ADDRSTRLEN> ip{};nice_address_to_string(&value->addr,ip.data());return json{{"address",numeric(ip.data())},{"port",nice_address_get_port(&value->addr)},{"type",int(value->type)},{"protocol",value->transport==NICE_CANDIDATE_TRANSPORT_UDP?"udp":"unexpected"}};};
        auto selected_local=candidate(local),selected_remote=candidate(remote);
        if(!granted(config,selected_remote.at("address"),selected_remote.at("port")) || local->transport!=NICE_CANDIDATE_TRANSPORT_UDP || remote->transport!=NICE_CANDIDATE_TRANSPORT_UDP){fail("transportRejected");return;}
        if(config.relay && local->type!=NICE_CANDIDATE_TYPE_RELAYED){fail("relayRequired");return;}
        reported=true;emit({{"type","received"},{"nonce",config.nonce},{"videoDecoded",!config.source && decoded.load()},{"dataVerified",true},{"dtlsConnected",true},{"transport",{{"local",selected_local},{"remote",selected_remote}}}});
    }
    void tick() {
        if(stopped)return;
        if(!config.source && offer_needed && !offered){offered=true;create_description();}
        if(bus)while(auto *message=gst_bus_pop_filtered(bus,GstMessageType(GST_MESSAGE_ERROR|GST_MESSAGE_EOS))){fail("pipelineFailed");gst_message_unref(message);}
        receipt();
    }
    void stop() {
        if(stopped.exchange(true))return;
        std::vector<GstPromise *> pending;
        {std::lock_guard lock(promise_mutex);for(auto *promise:promises)pending.push_back(gst_promise_ref(promise));}
        for(auto *promise:pending){gst_promise_interrupt(promise);gst_promise_unref(promise);}
        GstElement *old_pipeline,*old_rtc;NiceAgent *old_agent;GstBus *old_bus;
        {std::lock_guard lock(objects);old_pipeline=pipeline;old_rtc=rtc;old_agent=agent;old_bus=bus;pipeline=nullptr;rtc=nullptr;agent=nullptr;bus=nullptr;}
        if(old_pipeline)gst_element_set_state(old_pipeline,GST_STATE_NULL);
        if(old_agent) {
            // Retain the RTC/context while libnice removes TURN refreshes.
            // Merely unrefing a live relay agent skips its asynchronous close
            // and leaves refresh state alive after the remote route is gone.
            std::atomic<bool> closed{false};
            nice_agent_close_async(old_agent,+[](GObject *,GAsyncResult *,gpointer data){
                static_cast<std::atomic<bool> *>(data)->store(true);
            },&closed);
            while(!closed.load())g_main_context_iteration(nullptr,TRUE);
        }
        if(old_pipeline)gst_object_unref(old_pipeline);
        if(old_rtc)gst_object_unref(old_rtc);
        if(old_agent)g_object_unref(old_agent);
        if(old_bus)gst_object_unref(old_bus);
    }
};
ReadinessMediaTransport::ReadinessMediaTransport(const ReadinessMediaConfig &config):state(std::make_shared<State>(config)){try{state->build();}catch(...){state->stop();throw;}}
ReadinessMediaTransport::~ReadinessMediaTransport(){stop();}
void ReadinessMediaTransport::command(const json &value){if(!value.is_object() || !value.contains("schemaVersion") || value.at("schemaVersion")!=1 || !value.at("schemaVersion").is_number_integer() || !value.contains("type"))invalid();state->command(value);}
void ReadinessMediaTransport::tick(){state->safe([&]{state->tick();});}
std::vector<json> ReadinessMediaTransport::events(){std::lock_guard lock(state->queue_mutex);std::vector<json> result;while(!state->queued.empty()){result.push_back(std::move(state->queued.front()));state->queued.pop_front();}return result;}
bool ReadinessMediaTransport::failed()const{return state->failure;}
void ReadinessMediaTransport::stop(){if(state)state->stop();}
}
