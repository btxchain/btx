// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_NEGATIVE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_NEGATIVE_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Negative results stay queryable. A later promotion does not delete them.
 */
class SwarmGenerationNegatives {
public:
    std::size_t count() const { return m_rows.size(); }
    void add(std::string result);
    bool contains(const std::string& result) const;
    const std::vector<std::string>& rows() const { return m_rows; }

private:
    std::vector<std::string> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_NEGATIVE_H
