#include "owner_state.hpp"

int main(int argc, char **argv) {
    try {
        if (argc != 3 && argc != 4)
            return 2;
        if(argc==4) {
            std::string route=argv[3];
            if(route!="/readiness/begin" && route!="/readiness/inspect" && route!="/readiness/end" && route!="/readiness/reserve" && route!="/readiness/cancel")return 2;
            json body;std::cin>>body;
            auto response=traverse::owned_json_request(argv[1],static_cast<pid_t>(std::stol(argv[2])),route.c_str(),&body);
            auto verified=traverse::validate_owner_state(std::move(response.second),static_cast<pid_t>(std::stol(argv[2])));
            // Private fixture pipe only; the caller never exports lease secrets.
            std::cout<<json({{"status",response.first},{"response",verified}}).dump()<<'\n';
            return 0;
        }
        auto value = traverse::read_owner_state(argv[1], static_cast<pid_t>(std::stol(argv[2])));
        std::cout << json({{"schemaVersion", value.at("schemaVersion")},
                           {"verifiedProducerPid", value.at("pid")}})
                         .dump()
                  << '\n';
        return 0;
    } catch (const std::exception &) {
        std::cerr << "Synthetic owner state probe rejected producer\n";
        return 1;
    }
}
