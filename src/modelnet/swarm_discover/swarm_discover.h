// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISCOVER_H
#define BITCOIN_MODELNET_SWARM_DISCOVER_H

#include <modelnet/swarm_discover/codes.h>
#include <modelnet/swarm_discover/limits.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Peer discovery records.
 *
 * This stores offers, grants, and routes. It does not open a socket, scan
 * a network, or spend. Discovery is not network-scanning permission.
 * Routes enforce scope before performance. Route failover preserves the
 * object and grant bindings. Partition behavior exposes limits honestly.
 *
 * Offer stores one peer, its scope, its endpoint, and until_ms. An empty
 * peer, scope, or endpoint is PEER and stores nothing. scope must be lan,
 * wan, private, or public. Any other non-empty scope is SCOPE and stores
 * nothing. now_ms >= until_ms, including equality, is EXPIRED and stores
 * nothing. A second offer of the same peer is REPLAY and keeps the first.
 * The first valid offer returns true. connected() stays false. Offer does
 * not grant use.
 *
 * Grant authorizes one offered peer for the scope that was offered. An
 * unknown peer is PEER. A scope other than the offered scope is SCOPE and
 * nothing is granted. Success sets granted(peer) true. granted is not
 * connected.
 *
 * Use returns true for a granted peer. An unknown or ungranted peer is
 * NOT_AUTHORIZED and does not set connected(). A granted peer still leaves
 * connected() false. There is no socket.
 *
 * Scan always returns false with NOT_SCAN. It stores nothing.
 * bytes_moved() stays 0.
 *
 * Route stores the first route for an object. An empty object_id or
 * grant_id is ROUTE. An unknown or ungranted peer is NOT_AUTHORIZED. A
 * negative rtt is RTT. A later route whose grant_id differs is SCOPE and
 * does not replace the first, even when its rtt is lower. A later route
 * with the same grant_id and a strictly lower rtt replaces the peer and
 * the rtt and returns true. The object_id and the grant_id stay the same.
 * A same-grant rtt that is not strictly lower is RTT and does not replace
 * the peer.
 *
 * Partition(false) sets status to PARTITION and returns false.
 * Partition(true) sets status to LOCAL and returns true. Neither sets
 * connected() true. Neither invents an endpoint.
 *
 * launched(), gpu(), broadcast(), and connected() stay false.
 * automatic_spend() returns "0". bytes_moved() returns 0. No method sets
 * those live flags true.
 */
class SwarmDiscover {
public:
    bool Offer(const std::string& peer, const std::string& scope, const std::string& endpoint, int64_t until_ms, int64_t now_ms, std::string& err);
    bool Grant(const std::string& peer, const std::string& scope, std::string& err);
    bool Use(const std::string& peer, std::string& err);
    bool Scan(const std::string& prefix, std::string& err);
    bool Route(const std::string& object_id, const std::string& peer, const std::string& grant_id, int64_t rtt_ms, std::string& err);
    bool Partition(bool reachable, std::string& err);

    bool offered(const std::string& peer) const;
    bool granted(const std::string& peer) const;
    std::string scope_of(const std::string& peer) const;
    std::string endpoint_of(const std::string& peer) const;
    int64_t until_ms_of(const std::string& peer) const;

    bool routed(const std::string& object_id) const;
    std::string route_peer(const std::string& object_id) const;
    std::string route_grant_id(const std::string& object_id) const;
    int64_t route_rtt_ms(const std::string& object_id) const;

    const std::string& status() const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    bool connected() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    struct OfferRecord {
        std::string scope;
        std::string endpoint;
        int64_t until_ms{0};
        bool granted{false};
    };

    struct RouteRecord {
        std::string peer;
        std::string grant_id;
        int64_t rtt_ms{0};
    };

    std::map<std::string, OfferRecord> m_offers;
    std::map<std::string, RouteRecord> m_routes;
    std::string m_status;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISCOVER_H
