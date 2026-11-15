// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_BOOK_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_BOOK_H

#include <modelnet/swarm_sandboxgate/record.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Grants stored by a successful Grant, keyed by worker then path_prefix.
 * store refuses an unusable grant and a worker/prefix already present.
 * A refused store leaves the first capabilities, network flag, and until_ms.
 * There is no erase. Paths stay opaque strings.
 */
class SwarmSandboxGateBook {
public:
    bool worker_granted(const std::string& worker) const;
    bool prefix_held(const std::string& worker, const std::string& path_prefix) const;

    std::vector<SwarmSandboxGateGrant> grants_for(const std::string& worker) const;

    /**
     * Grants whose path_prefix is a strict bytewise prefix of path.
     * An unknown worker yields an empty vector. The book is not modified.
     */
    std::vector<SwarmSandboxGateGrant> matching(const std::string& worker, const std::string& path) const;

    /**
     * True when the worker has a grant with network set and now_ms < until_ms.
     * This is a policy query. It does not open a socket.
     */
    bool network_live(const std::string& worker, int64_t now_ms) const;

    /**
     * Store grant.
     * Refuses an unusable record and a duplicate worker/prefix.
     * On refusal the book is unchanged.
     */
    bool store(const SwarmSandboxGateGrant& grant);

private:
    std::map<std::string, std::map<std::string, SwarmSandboxGateGrant>> m_by_worker;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_BOOK_H
