// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <swapnet/transport.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <map>
#include <string>

// swapnet::Transport does framing and backpressure only (see transport.h).
// This drives one Transport with peers, frames and a clock that may step back,
// and checks what it bounds: the peer and queue caps, the per-peer inbound
// cap, the token bucket, the handshake, and that a closed or disabled peer
// leaves nothing queued. Payloads are parsed by the Python coordinator, which
// this target does not reach.
FUZZ_TARGET(swapnet_transport)
{
    using swapnet::PeerId;
    using swapnet::Transport;
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const std::string network(64, 'a');
    const std::string hello{"2:" + network};
    static constexpr std::array COMMANDS{"swhello", "swget", "swprov", "swrfq", "swquote", "swterms", "swreceipt", "version"};
    Transport transport{network, fdp.ConsumeBool()};

    struct Peer {
        std::int64_t ready_ms;
        std::int64_t max_ms;
        double spent{0};
        std::size_t queued{0};
        bool admitted{false};
    };
    std::map<PeerId, Peer> peers;
    std::int64_t now{fdp.ConsumeIntegralInRange<std::int64_t>(0, 1'000'000)};

    auto command = [&] { return fdp.ConsumeBool() ? std::string{fdp.PickValueInArray(COMMANDS)} : fdp.ConsumeRandomLengthString(12); };
    auto payload = [&]() -> std::string {
        switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
        case 0: return hello;
        case 1: return "2:" + std::string(64, 'b');
        case 2: return std::string(fdp.ConsumeIntegralInRange<std::size_t>(0, Transport::MAX_FRAME + 1), 'x');
        default: return fdp.ConsumeRandomLengthString(256);
        }
    };
    auto check_frame = [&](const swapnet::Frame& f) {
        assert(peers.count(f.peer));
        assert(Transport::KnownCommand(f.command));
        assert(!f.payload.empty() && f.payload.size() <= Transport::MAX_FRAME);
        if (f.command == "swhello") assert(f.payload == hello);
    };

    LIMITED_WHILE(fdp.ConsumeBool(), 2000)
    {
        const PeerId id{fdp.ConsumeIntegralInRange<PeerId>(-1, Transport::MAX_PEERS + 8)};
        CallOneOf(
            fdp,
            [&] {
                const bool enabled{fdp.ConsumeBool()};
                transport.SetEnabled(enabled);
                if (!enabled) peers.clear();
            },
            [&] {
                const auto before{transport.GetStats().peers};
                transport.PeerReady(id, now);
                if (transport.GetStats().peers == before + 1) {
                    assert(!peers.count(id));
                    peers.emplace(id, Peer{now, now});
                } else {
                    assert(transport.GetStats().peers == before);
                }
            },
            [&] { transport.RetryHellos(now); },
            [&] {
                transport.PeerClosed(id);
                peers.erase(id);
            },
            [&] {
                const std::string cmd{command()};
                const std::string data{payload()};
                auto it{peers.find(id)};
                if (it != peers.end()) it->second.max_ms = std::max(it->second.max_ms, now);
                if (!transport.Receive(id, cmd, data, now)) return;
                assert(it != peers.end());
                assert(Transport::KnownCommand(cmd) && !data.empty() && data.size() <= Transport::MAX_FRAME);
                Peer& p{it->second};
                // Every accepted frame was paid for: 16 tokens at the start, 1 per elapsed second.
                p.spent += 1.0 + static_cast<double>(data.size()) / 8192.0;
                assert(p.spent <= 16.0 + static_cast<double>(p.max_ms - p.ready_ms) / 1000.0 + 1e-6);
                if (cmd == "swhello") {
                    assert(!p.admitted && data == hello);
                    p.admitted = true;
                } else {
                    assert(p.admitted);
                    ++p.queued;
                    assert(p.queued <= 16);
                }
            },
            [&] {
                const std::string cmd{command()};
                if (!transport.Send(id, cmd, payload())) return;
                assert(peers.count(id) && peers.at(id).admitted && cmd != "swhello");
            },
            [&] {
                const auto f{transport.TakeInbound()};
                if (!f) return;
                check_frame(*f);
                assert(f->command != "swhello");
                Peer& p{peers.at(f->peer)};
                assert(p.queued > 0);
                --p.queued;
            },
            [&] {
                if (const auto f{transport.TakeOutbound()}) check_frame(*f);
            },
            [&] {
                const auto f{transport.TakeOutboundForPeer(id)};
                if (!f) return;
                assert(f->peer == id);
                check_frame(*f);
            },
            // Small steps both ways: stepping the clock back must earn no tokens.
            [&] { now += fdp.ConsumeIntegralInRange<std::int64_t>(-20'000, 20'000); });

        const auto stats{transport.GetStats()};
        std::size_t admitted{0}, queued{0};
        for (const auto& [_, p] : peers) {
            admitted += p.admitted;
            queued += p.queued;
        }
        assert(stats.peers == peers.size() && stats.peers <= Transport::MAX_PEERS);
        assert(stats.admitted == admitted && transport.AdmittedPeers().size() == admitted);
        assert(stats.inbound == queued && stats.inbound <= Transport::MAX_QUEUE);
        assert(stats.outbound <= Transport::MAX_QUEUE);
        if (!stats.enabled) assert(stats.peers == 0 && stats.inbound == 0 && stats.outbound == 0);
    }
}
