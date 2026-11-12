#include "wayland_controller.hpp"
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <poll.h>
#include <thread>
#include <unistd.h>

using Json=nlohmann::json;
using Controller=traverse::WaylandController;
namespace {
void emit(const Json &row){std::cout<<row.dump()<<std::endl;}
Json failure(const Controller::Error &error){return {{"error",error.what()},{"failure",static_cast<int>(error.failure)}};}
Json snapshot(const Controller::Snapshot &value){
    return {{"event","state"},{"desktop",value.desktop?*value.desktop:Json(nullptr)},
        {"pid",value.worker_pid},{"accepting",value.accepting},{"terminal",value.terminal},
        {"inputReady",value.input_ready()},{"exit",value.exit_status?Json(*value.exit_status):Json(nullptr)},
        {"error",value.error}};
}
}
int main(int argc,char **argv){
    if(argc!=2)return 2;
    try {
        // Deliberately let the constructor's caller thread exit. The library's
        // surviving lifecycle thread must remain the guardian's real creator.
        std::unique_ptr<Controller> owner;
        std::thread constructor([&]{owner=std::make_unique<Controller>(argv[1]);});constructor.join();
        emit({{"event","constructed"}});
        std::map<std::uint64_t,std::future<Json>> pending;
        std::shared_future<void> stopped;
        std::string incoming,last;
        bool input=true;
        int flags=fcntl(0,F_GETFL);if(flags<0 || fcntl(0,F_SETFL,flags|O_NONBLOCK))return 2;
        for(;;){
            auto state=snapshot(owner->snapshot());
            auto encoded=state.dump();if(encoded!=last){emit(state);last=encoded;}
            for(auto item=pending.begin();item!=pending.end();){
                if(item->second.wait_for(std::chrono::seconds(0))!=std::future_status::ready){++item;continue;}
                Json row={{"event","reply"},{"token",item->first}};
                try{row["reply"]=item->second.get();}
                catch(const Controller::Error &error){row.update(failure(error));}
                emit(row);item=pending.erase(item);
            }
            if(state["terminal"].get<bool>()){
                if(!stopped.valid())stopped=owner->stop();
                Json row={{"event","stopped"}};
                try{stopped.get();row["ok"]=true;}
                catch(const Controller::Error &error){row["ok"]=false;row.update(failure(error));}
                emit(row);return 0;
            }
            pollfd descriptors[]={{input?0:-1,POLLIN,0},{owner->state_descriptor(),POLLIN,0}};
            int ready;do{ready=poll(descriptors,2,-1);}while(ready<0 && errno==EINTR);
            if(ready<0)throw std::runtime_error("Probe poll failed");
            if(descriptors[1].revents){char bytes[256];while(read(descriptors[1].fd,bytes,sizeof(bytes))>0){}}
            if(descriptors[0].revents&(POLLIN|POLLHUP)){
                char bytes[8192];auto count=read(0,bytes,sizeof(bytes));
                if(count==0){input=false;stopped=owner->stop();}
                else if(count>0){
                    incoming.append(bytes,static_cast<std::size_t>(count));
                    for(std::size_t newline;(newline=incoming.find('\n'))!=std::string::npos;){
                        auto command=Json::parse(incoming.substr(0,newline));incoming.erase(0,newline+1);
                        if(command.value("action",std::string{})=="stop"){
                            stopped=owner->stop();emit({{"event","stop-fenced"},{"accepting",owner->snapshot().accepting}});
                        }else{
                            auto token=command.at("token").get<std::uint64_t>();
                            pending.emplace(token,owner->request(command.at("command")));
                        }
                    }
                }else if(errno!=EAGAIN && errno!=EINTR)throw std::runtime_error("Probe stdin failed");
            }
        }
    }catch(const std::exception &error){std::cerr<<error.what()<<std::endl;return 1;}
}
