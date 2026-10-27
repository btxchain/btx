// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_BRANCH_H
#define BITCOIN_MODELNET_SWARM_GENERATION_BRANCH_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationBranchRow {
    std::string left;
    std::string right;
};

/**
 * Experimental branches opened when two results are not compatible.
 * A branch is a fork. It does not store averaged weights.
 */
class SwarmGenerationBranches {
public:
    bool forked() const { return !m_rows.empty(); }
    std::size_t count() const { return m_rows.size(); }
    void add(std::string left, std::string right);
    const std::vector<SwarmGenerationBranchRow>& rows() const { return m_rows; }

private:
    std::vector<SwarmGenerationBranchRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_BRANCH_H
