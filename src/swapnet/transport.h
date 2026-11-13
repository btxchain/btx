// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SWAPNET_TRANSPORT_H
#define BTX_SWAPNET_TRANSPORT_H
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
namespace swapnet {
using PeerId = std::int64_t;
struct Frame { PeerId peer; std::string command; std::string payload; };
struct Stats { std::size_t peers, admitted, inbound, outbound; std::uint64_t rejected; bool enabled; };
// This class performs framing/backpressure only. The in-process coordinator verifies
// identity signatures and semantics. No wallet, consensus, AddrMan or BanMan access.
class Transport {
public:
    explicit Transport(std::string network, bool enabled = true);
    void SetEnabled(bool enabled);
    void PeerReady(PeerId peer, std::int64_t monotonic_ms);
    void PeerClosed(PeerId peer);
    bool Receive(PeerId peer, const std::string& command, const std::string& payload, std::int64_t monotonic_ms);
    bool Send(PeerId peer, const std::string& command, const std::string& payload);
    std::optional<Frame> TakeInbound();
    std::optional<Frame> TakeOutbound();
    std::optional<Frame> TakeOutboundForPeer(PeerId peer);
    std::vector<PeerId> AdmittedPeers() const;
    Stats GetStats() const;
    static bool KnownCommand(const std::string& command);
    static constexpr std::size_t MAX_FRAME = 65536;
    static constexpr std::size_t MAX_QUEUE = 256;
    static constexpr std::size_t MAX_PEERS = 128;
private:
    struct Peer { bool admitted{false}; double tokens{16}; std::int64_t last_ms{0}; std::size_t queued{0}; };
    std::string m_network;
    bool m_enabled;
    mutable std::mutex m_mutex;
    std::map<PeerId,Peer> m_peers;
    std::deque<Frame> m_in,m_out;
    std::uint64_t m_rejected{0};
};
}
#endif
