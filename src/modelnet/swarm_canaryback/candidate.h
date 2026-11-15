// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_CANDIDATE_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_CANDIDATE_H

#include <string>

namespace modelnet {

/**
 * The staged candidate.
 * store replaces the id and clears the adopted mark. The active id
 * is not held here. clear drops the id. mark_adopted leaves the id
 * in place so a second Adopt of this stage is a replay.
 */
class SwarmCanaryBackCandidate {
public:
    bool held() const;
    bool adopted() const;
    const std::string& id() const;

    void store(const std::string& id);
    void mark_adopted();
    void clear();

private:
    std::string m_id;
    bool m_adopted{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_CANDIDATE_H
