// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_CANDIDATE_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_CANDIDATE_H

#include <string>

namespace modelnet {

/**
 * The staged candidate. An empty id means nothing is staged.
 * replace stores a non-empty id and drops the previous candidate.
 * clear drops the candidate. Neither call changes the active id.
 */
class SwarmPromoteCandidate {
public:
    bool held() const { return !m_id.empty(); }
    const std::string& id() const { return m_id; }

    bool replace(const std::string& id);
    void clear();

private:
    std::string m_id;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_CANDIDATE_H
