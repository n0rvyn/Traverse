#include "child.hpp"
int main(int argc,char **argv) {
    try {
        if(argc!=2)throw std::runtime_error("Worker path missing");
        json request={{"schemaVersion",1},{"target",{{"host","owner.example.test"},{"port",9},
            {"basePath","/"},{"address","127.0.0.1"},{"caFile",""}}},
            {"lease",{{"instance",std::string(32,'a')},{"id",std::string(32,'b')},
                {"token",std::string(64,'c')},{"nonce",std::string(64,'d')}}}};
        OwnedOperation operation(argv[1],request.dump());
        auto watchdog=Clock::now()+std::chrono::seconds(5);
        while(Clock::now()<watchdog) {
            if(auto result=operation.poll()) {
                auto row=json::parse(result->output);
                auto status=row.at("status").get<std::string>();
                if(status!="connectionFailed" || result->exit_status!=1 || operation.id()!=-1)
                    throw std::runtime_error("Owned verifier returned "+status+" instead of connectionFailed");
                std::cout<<"Actual OwnedOperation supervisor invocation accepted and exactly reaped\n";
                return 0;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        throw std::runtime_error("Owned verifier watchdog expired");
    }catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
}
