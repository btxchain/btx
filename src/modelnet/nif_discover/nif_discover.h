// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_DISCOVER_NIF_DISCOVER_H
#define BITCOIN_MODELNET_NIF_DISCOVER_NIF_DISCOVER_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** An empty peer, or a connect of an unknown peer. Nothing new is stored. */
inline constexpr char kNifDiscoverPeer[] = "PEER";

/** The peer was not authenticated. authority() is not set. */
inline constexpr char kNifDiscoverAuth[] = "AUTH";

/** A multicast hint is not a connectable peer. */
inline constexpr char kNifDiscoverHint[] = "HINT";

/**
 * Local discovery on one physical host. No socket is opened.
 *
 * Hint records one peer. An empty peer is PEER and stores nothing.
 * via_multicast true stores that peer as a hint only. hint_only() stays
 * true and authority() stays false while no non-multicast authenticated
 * peer is recorded. authenticated false stores the peer, returns AUTH,
 * and does not set authority(). authenticated true on a non-multicast
 * hint sets authority() for that one peer.
 *
 * A second Hint of the same peer is NIFDT_REPLAY. The first record stays,
 * including its authentication bit.
 *
 * Connect returns true only when that peer is authoritative, and counts
 * the peer once. A multicast-only peer is HINT and does not connect.
 * connected() counts only authoritative connects.
 *
 * Wan returns false with NIFDT_NO_ROUTE. Scan returns false with
 * NIFDT_NOT_SCAN. physical_hosts() is 1. ranks() counts stored local
 * identities and may be 2. hosts() stays 1. Those identities are not a
 * second machine.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 */
class NifDiscover {
public:
    bool Hint(const std::string& peer, bool via_multicast, bool authenticated, std::string& err);
    bool Connect(const std::string& peer, std::string& err);
    bool Wan(std::string& err);
    bool Scan(std::string& err);

    bool hint_only() const;
    bool authority() const;
    bool authority(const std::string& peer) const;
    bool hinted(const std::string& peer) const;
    bool peer_authenticated(const std::string& peer) const;
    bool peer_multicast(const std::string& peer) const;
    int64_t connected() const;
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t ranks() const { return static_cast<int64_t>(m_peers.size()); }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }

private:
    struct Peer {
        std::string name;
        bool via_multicast{false};
        bool authenticated{false};
        bool connected{false};
    };

    Peer* Find(const std::string& peer);
    const Peer* Find(const std::string& peer) const;
    static bool IsAuthoritative(const Peer& row);

    std::vector<Peer> m_peers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_DISCOVER_NIF_DISCOVER_H
