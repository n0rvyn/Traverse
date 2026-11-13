#include <agent.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <unistd.h>
using json=nlohmann::json;
#include <memory>
#include <vector>
#define CHECK(value) do { if (!(value)) throw std::runtime_error("Check failed: " #value); } while (false)
struct Unref {void operator()(NiceAgent *p)const{g_object_unref(p);}};
using Agent=std::unique_ptr<NiceAgent,Unref>;
Agent make_agent(){return Agent(nice_agent_new(g_main_context_default(),NICE_COMPATIBILITY_RFC5245));}
int add_candidate(NiceAgent *agent,guint stream,const char *ip,unsigned port) {
    auto *candidate=nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
    candidate->transport=NICE_CANDIDATE_TRANSPORT_UDP;candidate->stream_id=stream;candidate->component_id=1;
    candidate->priority=2130706431;g_strlcpy(candidate->foundation,"policy",sizeof(candidate->foundation));
    CHECK(nice_address_set_from_string(&candidate->addr,ip));nice_address_set_port(&candidate->addr,port);candidate->base_addr=candidate->addr;
    GSList item{candidate,nullptr};auto result=nice_agent_set_remote_candidates(agent,stream,1,&item);
    nice_candidate_free(candidate);return result;
}
void contracts(int argc,char **argv) {
    g_test_init(&argc,&argv,nullptr);
    {
        auto agent=make_agent();gchar **unset=nullptr;g_object_get(agent.get(),"probe-peer-allowlist",&unset,nullptr);CHECK(!unset);
        const gchar *empty[]={nullptr};g_object_set(agent.get(),"probe-peer-allowlist",empty,nullptr);
        gchar **value=nullptr;g_object_get(agent.get(),"probe-peer-allowlist",&value,nullptr);CHECK(value && !value[0]);g_strfreev(value);
        auto stream=nice_agent_add_stream(agent.get(),1);CHECK(add_candidate(agent.get(),stream,"127.0.0.1",33333)<=0);
        nice_agent_remove_stream(agent.get(),stream);
    }
    {
        auto agent=make_agent();const gchar *values[]={"127.0.0.1|33333","::1|33334",nullptr};
        g_object_set(agent.get(),"probe-peer-allowlist",values,nullptr);
        gboolean tcp=TRUE;g_object_get(agent.get(),"ice-tcp",&tcp,nullptr);CHECK(!tcp);
        g_test_expect_message("libnice",G_LOG_LEVEL_WARNING,"*only permits UDP*");
        g_object_set(agent.get(),"ice-tcp",TRUE,nullptr);g_test_assert_expected_messages();
        g_object_get(agent.get(),"ice-tcp",&tcp,nullptr);CHECK(!tcp);
        auto stream=nice_agent_add_stream(agent.get(),1);
        CHECK(add_candidate(agent.get(),stream,"127.0.0.1",33333)==1);
        CHECK(add_candidate(agent.get(),stream,"127.0.0.1",33334)<=0);
        CHECK(add_candidate(agent.get(),stream,"127.0.0.2",33333)<=0);
        CHECK(add_candidate(agent.get(),stream,"::1",33334)==1);
        CHECK(add_candidate(agent.get(),stream,"::1",33333)<=0);
        const gchar *changed[]={"127.0.0.1|44444",nullptr};
        g_test_expect_message("libnice",G_LOG_LEVEL_WARNING,"*once before creating streams*");
        g_object_set(agent.get(),"probe-peer-allowlist",changed,nullptr);g_test_assert_expected_messages();
        gchar **readback=nullptr;g_object_get(agent.get(),"probe-peer-allowlist",&readback,nullptr);
        CHECK(readback && std::string(readback[0])==values[0] && std::string(readback[1])==values[1] && !readback[2]);g_strfreev(readback);
        nice_agent_remove_stream(agent.get(),stream);
        g_test_expect_message("libnice",G_LOG_LEVEL_WARNING,"*once before creating streams*");
        g_object_set(agent.get(),"probe-peer-allowlist",changed,nullptr);g_test_assert_expected_messages();
    }
    for(auto bad:{"localhost|33333","127.0.0.1|0","127.0.0.1|65536","127.0.0.1|-1","127.0.0.1|33x","127.0.0.1", "|33333"}) {
        auto agent=make_agent();const gchar *values[]={bad,nullptr};
        g_test_expect_message("libnice",G_LOG_LEVEL_WARNING,"*requires numeric address*UDP-port tuples*");
        g_object_set(agent.get(),"probe-peer-allowlist",values,nullptr);g_test_assert_expected_messages();
        gchar **readback=nullptr;g_object_get(agent.get(),"probe-peer-allowlist",&readback,nullptr);CHECK(!readback);
    }
    std::cout<<"Frozen probe peer property and numeric IPv4/IPv6 candidate contracts passed\n";
}
int main(int argc,char **argv) {
    if(argc==1){contracts(argc,argv);return 0;}
    if(argc!=3 && argc!=4)return 2;
    auto *context=g_main_context_default();
    NiceAgent *agent=nice_agent_new(context,NICE_COMPATIBILITY_RFC5245);
    if(!agent)return 3;
    g_object_set(agent,"controlling-mode",FALSE,"ice-tcp",FALSE,"upnp",FALSE,nullptr);
    NiceAddress address;nice_address_init(&address);nice_address_set_from_string(&address,"127.0.0.1");
    if(!nice_agent_add_local_address(agent,&address))return 4;
    if(argc==4) {
        std::string tuple="127.0.0.1|"+std::string(argv[2]);
        const gchar *values[]={tuple.c_str(),nullptr};
        g_object_set(agent,"probe-peer-allowlist",values,nullptr);
        gchar **readback=nullptr;g_object_get(agent,"probe-peer-allowlist",&readback,nullptr);
        bool matches=readback && readback[0] && tuple==readback[0] && !readback[1];
        g_strfreev(readback);if(!matches)return 8;
    }
    guint stream=nice_agent_add_stream(agent,1);unsigned port=std::stoul(argv[1]);
    nice_agent_set_port_range(agent,stream,1,port,port);
    nice_agent_attach_recv(agent,stream,1,context,+[](NiceAgent*,guint,guint,guint,gchar*,gpointer){},nullptr);
    if(!nice_agent_set_remote_credentials(agent,stream,"remoteprobe","remoteprobeabcdefghijklmnop"))return 5;
    NiceCandidate *candidate=nice_candidate_new(NICE_CANDIDATE_TYPE_HOST);
    candidate->transport=NICE_CANDIDATE_TRANSPORT_UDP;candidate->stream_id=stream;candidate->component_id=1;
    candidate->priority=2130706431;g_strlcpy(candidate->foundation,"probe",sizeof(candidate->foundation));
    candidate->addr=address;nice_address_set_port(&candidate->addr,std::stoul(argv[2]));candidate->base_addr=candidate->addr;
    GSList item{candidate,nullptr};
    if(nice_agent_set_remote_candidates(agent,stream,1,&item)!=1)return 6;
    nice_candidate_free(candidate);
    g_signal_connect(agent,"candidate-gathering-done",G_CALLBACK((+[](NiceAgent *agent,guint id,gpointer){
        gchar *username=nullptr,*password=nullptr;
        if(!nice_agent_get_local_credentials(agent,id,&username,&password))return;
        std::cout<<json({{"ufrag",username},{"password",password}}).dump()<<std::endl;
        g_free(username);g_free(password);
    })),nullptr);
    if(!nice_agent_gather_candidates(agent,stream))return 7;
    for(;;) {
        while(g_main_context_iteration(context,FALSE)){}
        pollfd input{STDIN_FILENO,POLLIN,0};
        if(poll(&input,1,5)>0){char byte;auto count=read(STDIN_FILENO,&byte,1);if(count<=0)break;}
    }
    nice_agent_remove_stream(agent,stream);g_object_unref(agent);return 0;
}
