#include "readiness_challenge.hpp"
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

static void require(bool value,const char *message) {
    if(!value)throw std::runtime_error(message);
}
int main() {
    using Challenges=traverse::ReadinessChallenge;
    try {
        Challenges owner;
        auto first=owner.begin(), second=owner.begin();
        require(owner.valid_token(first.token) && owner.valid_token(second.token),"Owner-issued credentials authenticate");
        require(!owner.valid_token("") && !owner.valid_token(std::string(64,'z')),"Unknown credentials rejected");
        require(first.instance==second.instance && first.id!=second.id &&
                first.token!=second.token && first.nonce!=second.nonce,"Independent lease identities");
        require(!owner.consume(first.id,second.token,first.nonce),"Wrong bearer rejected");
        require(!owner.consume(first.id,first.token,second.nonce),"Wrong nonce rejected");
        require(!owner.consume(second.id,first.token,first.nonce),"Cross-lease rejected");
        require(!owner.consume("",first.token,first.nonce),"Unknown lease rejected");
        auto initial=owner.inspect(first.id);
        require(initial && !initial->receipt,"Negatives do not consume authority");
        auto receipt=owner.consume(first.id,first.token,first.nonce);
        require(receipt && receipt->instance==first.instance && receipt->id==first.id &&
                receipt->nonce==first.nonce && receipt->observed_monotonic_ms>=0,"Actual receipt bound");
        require(!owner.consume(first.id,first.token,first.nonce),"Replay rejected");
        require(!owner.valid_token(first.token),"Consumed credential no longer authenticates");
        require(owner.inspect(first.id)->receipt.has_value(),"Owner observes consumption");
        require(owner.end(first.id) && !owner.inspect(first.id) &&
                !owner.consume(first.id,first.token,first.nonce),"End revokes observed lease");
        require(!owner.end(first.id),"Unknown end distinguished");
        require(!owner.valid_token(first.token),"End removes credential index");
        require(owner.end(second.id) && !owner.consume(second.id,second.token,second.nonce),
                "End revokes unused lease");
        require(!owner.valid_token(second.token),"End revokes unused credential index");
        Challenges next;
        auto other=next.begin();
        require(other.instance!=first.instance &&
                !next.consume(first.id,first.token,first.nonce),"Restart isolates instance");
        auto concurrent=owner.begin();
        std::atomic<bool> start{false};std::atomic<unsigned> waiting{0};
        std::vector<unsigned> winners(8);std::vector<std::thread> threads;
        for(std::size_t i=0;i<winners.size();++i)threads.emplace_back([&,i] {
            ++waiting;while(!start.load())std::this_thread::yield();
            winners[i]=owner.consume(concurrent.id,concurrent.token,concurrent.nonce).has_value();
        });
        while(waiting.load()!=winners.size())std::this_thread::yield();
        start=true;for(auto &thread:threads)thread.join();
        unsigned total=0;for(auto value:winners)total+=value;
        require(total==1,"Concurrent consumption has exactly one winner");
        require(owner.end(concurrent.id),"Concurrent receipt explicitly released");
        const std::string early(32,'1');
        require(owner.cancel_reserved(early) && owner.cancel_reserved(early),"Cancellation is idempotent before publication");
        require(!owner.reserve(early) && !owner.inspect(early),"Late reserve cannot resurrect cancelled authority");
        const std::string chosen(32,'2');auto reserved=owner.reserve(chosen);
        require(reserved && reserved->id==chosen && owner.valid_token(reserved->token),"Known-ID reservation failed");
        require(!owner.reserve(chosen),"Reserved ID reused");
        require(owner.cancel_reserved(chosen) && !owner.valid_token(reserved->token) && !owner.inspect(chosen),"Cancel did not revoke credential");
        require(!owner.reserve(chosen) && !owner.consume(chosen,reserved->token,reserved->nonce),"Revoked reservation revived");
        auto ordinary=owner.begin();
        require(!owner.cancel_reserved(ordinary.id) && owner.valid_token(ordinary.token),"Reservation cancel touched unrelated classic lease");
        require(owner.end(ordinary.id),"Classic lease cleanup failed");
        const std::string ended(32,'3');require(owner.reserve(ended).has_value() && owner.end(ended) && !owner.reserve(ended),"Classic end of reservation lost its denial");
        for(unsigned round=0;round<16;++round) {
            auto id=std::string(30,'4')+"0123456789abcdef"[round]+"0";
            std::optional<Challenges::Lease> race;std::atomic<bool> begin_race{false};
            std::thread creator([&]{while(!begin_race.load())std::this_thread::yield();race=owner.reserve(id);});
            begin_race=true;require(owner.cancel_reserved(id),"Concurrent reservation cancellation failed");creator.join();
            require(!owner.reserve(id) && !owner.inspect(id),"Concurrent late creation survived cancel");
            if(race)require(!owner.valid_token(race->token),"Concurrent credential survived cancellation");
        }
        require(next.reserve(early).has_value(),"New service instance did not reset denial metadata");
        bool invalid=false;try{owner.reserve("not-an-id");}catch(const std::invalid_argument &){invalid=true;}
        require(invalid,"Invalid reservation ID accepted");
        auto remaining=next.consume(other.id,other.token,other.nonce);
        require(remaining.has_value(),"Independent instance remains usable");
        std::cout<<"Readiness leases: isolation, wrong bearer/nonce, replay, cancellation, restart and concurrent one-use passed\n";
        return 0;
    } catch(const std::exception &error) {
        std::cerr<<error.what()<<'\n';return 1;
    }
}
