#include <swapnet/transport.h>
#include <cassert>
#include <iostream>
#include <thread>
using namespace swapnet;

// Exchange pending frames until both queues drain, as SendMessages does.
static void exchange(Transport& left, Transport& right, std::int64_t now) {
    for (unsigned round = 0; round < 8; ++round) {
        bool sent = false;
        while (auto frame = left.TakeOutbound()) {
            right.Receive(1, frame->command, frame->payload, now);
            sent = true;
        }
        while (auto frame = right.TakeOutbound()) {
            left.Receive(1, frame->command, frame->payload, now);
            sent = true;
        }
        if (!sent) return;
    }
    assert(false && "hello exchange did not drain");
}

static void test_paired_admission(bool miss_left, bool miss_right) {
    const std::string network(64, 'a');
    Transport left(network), right(network);
    left.PeerReady(1, 1000);
    right.PeerReady(1, 1000);
    const auto first_left = left.TakeOutbound();
    const auto first_right = right.TakeOutbound();
    assert(first_left && first_right);
    if (!miss_left) assert(right.Receive(1, first_left->command, first_left->payload, 1000));
    if (!miss_right) assert(left.Receive(1, first_right->command, first_right->payload, 1000));
    left.RetryHellos(5999);
    right.RetryHellos(5999);
    // No retry before five seconds. Any pending frames are handshake replies.
    if (miss_left && miss_right) {
        assert(!left.TakeOutbound() && !right.TakeOutbound());
        assert(left.GetStats().admitted == 0 && right.GetStats().admitted == 0);
    }
    exchange(left, right, 5999);
    left.RetryHellos(6000);
    right.RetryHellos(6000);
    exchange(left, right, 6000);
    assert(left.GetStats().admitted == 1);
    assert(right.GetStats().admitted == 1);
    assert(left.Send(1, "swprov", "{}"));
    assert(right.Send(1, "swprov", "{}"));
    exchange(left, right, 7000);
    const auto received_left = left.TakeInbound();
    const auto received_right = right.TakeInbound();
    assert(received_left && received_left->command == "swprov");
    assert(received_right && received_right->command == "swprov");
    // Established peers do not restart discovery or create a hello loop.
    assert(!left.Receive(1, "swhello", "2:" + network, 12000));
    assert(!right.Receive(1, "swhello", "2:" + network, 12000));
    left.RetryHellos(12000);
    right.RetryHellos(12000);
    assert(!left.TakeOutbound() && !right.TakeOutbound());
}

static void test_hello_with_full_queue() {
    const std::string network(64, 'a');
    Transport transport(network);
    transport.PeerReady(1, 1000);
    transport.TakeOutbound();
    for (int id = 2; id <= 9; ++id) {
        transport.PeerReady(id, 1000);
        assert(transport.Receive(id, "swhello", "2:" + network, 1000));
    }
    while (transport.TakeOutbound()) {}
    for (int id = 2; id <= 9; ++id) {
        for (int n = 0; n < 32; ++n) assert(transport.Send(id, "swprov", "{}"));
    }
    assert(transport.GetStats().outbound == Transport::MAX_QUEUE);
    assert(!transport.Receive(1, "swhello", "2:" + network, 2000));
    assert(transport.GetStats().admitted == 8);
    assert(transport.TakeOutbound());
    assert(transport.Receive(1, "swhello", "2:" + network, 3000));
    assert(transport.GetStats().admitted == 9);
    assert(transport.GetStats().outbound == Transport::MAX_QUEUE);
    const auto reply = transport.TakeOutboundForPeer(1);
    assert(reply && reply->command == "swhello");
}

int main() {
    const std::string network(64,'a');Transport t(network);
    assert(t.GetStats().enabled);t.PeerReady(1,1000);
    assert(t.TakeOutbound()->payload=="2:"+network);
    t.RetryHellos(2000);assert(!t.TakeOutbound());
    t.RetryHellos(7000);assert(t.TakeOutbound()->command=="swhello");
    assert(!t.Receive(1,"swprov","{}",1000));
    assert(!t.Receive(1,"swhello","2:"+std::string(64,'b'),1000));
    assert(!t.Receive(99,"swhello","2:"+network,1000));
    assert(!t.TakeOutbound());
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
    test_paired_admission(false, false);
    test_paired_admission(true, false);
    test_paired_admission(false, true);
    test_paired_admission(true, true);
    test_hello_with_full_queue();
    std::cout<<"transport: all assertions passed\n";
}
