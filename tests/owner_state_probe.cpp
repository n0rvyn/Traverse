#include "owner_state.hpp"

int main(int argc, char **argv) {
    try {
        if (argc != 3)
            return 2;
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
