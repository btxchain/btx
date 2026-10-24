// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_BOOK_H
#define BITCOIN_MODELNET_SWARM_NATPUB_BOOK_H

#include <modelnet/swarm_natpub/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Endpoints recorded by Claim, keyed by the endpoint string.
 * store refuses an empty endpoint and an endpoint already present.
 * A refused store leaves the first endpoint in place.
 * There is no method that publishes a record, moves bytes, opens a
 * connection, or marks the claim launched.
 */
class SwarmNatPubBook {
public:
    bool contains(const std::string& endpoint) const;
    std::string endpoint_of(const std::string& endpoint) const;
    std::size_t size() const;

    /** True when any kept claim is marked published. None are. */
    bool published() const;

    /** True when this endpoint is marked published. A stored claim is not. */
    bool published_of(const std::string& endpoint) const;

    /** Sum of bytes on every kept claim. Each claim is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept claim is marked connected. None are. */
    bool connected() const;

    /** True when this endpoint is marked connected. None are. */
    bool connected_of(const std::string& endpoint) const;

    /** True when any kept claim is marked launched. None are. */
    bool launched() const;

    /**
     * Record endpoint.
     * Refuses an empty endpoint and an endpoint already present. On
     * refusal the book is unchanged.
     */
    bool store(const std::string& endpoint);

private:
    std::map<std::string, SwarmNatPubRecord> m_claims;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_BOOK_H
