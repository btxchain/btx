// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_RESULT_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_RESULT_H

#include <string>

namespace modelnet {

/**
 * The latest digest a sha256 run stored, and whether any run has stored one.
 * ran() is false until Store is called.
 * Store is called only after a digest has been computed.
 * A refused Execute does not call Store, so a previous digest stays.
 */
class SwarmAgentExecResult {
public:
    void Store(const std::string& digest);
    bool ran() const;
    std::string result() const;

private:
    bool m_ran{false};
    std::string m_digest;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_RESULT_H
