// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_BOOK_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_BOOK_H

#include <modelnet/swarm_ckpttrust/record.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Claims recorded by Trust, keyed by claim.
 * store refuses an empty claim and a claim already present.
 * A refused store leaves the first claim in place.
 * There is no method that marks a record trusted, moves bytes,
 * marks the gpu busy, or marks the claim launched.
 */
class SwarmCheckpointTrustBook {
public:
    bool contains(const std::string& claim) const;
    std::string claim_of(const std::string& claim) const;
    std::size_t size() const;

    /** True when any kept claim is trusted. None are. */
    bool trusted() const;

    /** Sum of bytes on every kept claim. Each claim is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept claim marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept claim is marked launched. None are. */
    bool launched() const;

    /**
     * Record claim.
     * Refuses an empty claim and a claim already present. On refusal the
     * book is unchanged.
     */
    bool store(const std::string& claim);

private:
    std::map<std::string, SwarmCheckpointTrustRecord> m_claims;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_BOOK_H
