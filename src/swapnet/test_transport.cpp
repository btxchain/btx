#include <swapnet/transport.h>
#include <cassert>
#include <iostream>
#include <thread>
using namespace swapnet;
int main() {
    const std::string network(64,'a');Transport t(network);
    assert(t.GetStats().enabled);t.PeerReady(1,1000);
    assert(t.TakeOutbound()->payload=="2:"+network);
    t.RetryHellos(2000);assert(!t.TakeOutbound());
    t.RetryHellos(7000);assert(t.TakeOutbound()->command=="swhello");
    assert(!t.Receive(1,"swprov","{}",1000));
    assert(!t.Receive(1,"swhello","2:"+std::string(64,'b'),1000));
    assert(t.Receive(1,"swhello","2:"+network,2000));
    assert(!t.Receive(1,"swhello","2:"+network,3000));
    assert(t.Receive(1,"swprov","{}",4000));
    assert(t.TakeInbound()->command=="swprov");
    assert(!t.Receive(1,"swprov",std::string(65537,'x'),5000));
    assert(!t.Receive(1,"walletpass","{}",5000));
    for(int i=0;i<500;++i)t.Receive(1,"swrfq","{}",6000);
    assert(t.GetStats().inbound<=16);assert(t.GetStats().rejected>0);
    std::thread a([&](){for(int i=0;i<1000;++i)t.Send(1,"swquote","{}");});
    std::thread b([&](){for(int i=0;i<1000;++i)t.GetStats();});a.join();b.join();
    assert(t.GetStats().outbound<=Transport::MAX_QUEUE);
    t.PeerClosed(1);assert(t.GetStats().peers==0&&t.GetStats().inbound==0&&t.GetStats().outbound==0);
    for(int i=0;i<1000;++i)t.PeerReady(i,10000);
    assert(t.GetStats().peers==Transport::MAX_PEERS);
    t.SetEnabled(false);assert(!t.GetStats().enabled&&t.GetStats().peers==0);
    t.PeerReady(1001,20000);assert(t.GetStats().peers==0);
    std::cout<<"transport: all assertions passed\n";
}
