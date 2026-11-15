// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RESULTSHARE_H
#define BTX_MODELNET_SWARM_RESULTSHARE_H

#include <map>
#include <set>
#include <string>

namespace modelnet {

/**
 * In-memory share of a published result hash with named consumers.
 *
 * Publish stores one hash for a result id. Attach records a consumer only
 * when that consumer presents the stored hash. A later Publish of the same
 * id leaves the first hash in place. A hash that does not match records
 * nobody.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmResultShare {
public:
    /**
     * An empty result id or an empty hash is RESULT. A second Publish of an
     * id already stored is REPLAY and leaves the first hash. Success stores
     * the hash and clears err.
     */
    bool Publish(const std::string& result_id, const std::string& hash, std::string& err);

    /**
     * An unknown result id is RESULT. An empty consumer is CONSUMER. A hash
     * that differs from the stored hash is CONFLICT and does not record the
     * consumer. The same consumer again is REPLAY. Success records the
     * consumer and clears err.
     */
    bool Attach(const std::string& result_id, const std::string& consumer, const std::string& hash,
                std::string& err);

    /** True when that consumer was recorded for the result. */
    bool Attached(const std::string& result_id, const std::string& consumer) const;

private:
    struct Share {
        std::string hash;
        std::set<std::string> consumers;
    };

    std::map<std::string, Share> m_shares;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RESULTSHARE_H
