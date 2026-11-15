// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_EARNED_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_EARNED_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Earned rows for one swarm, one row per work id.
 * atoms below 0 is refused and nothing is stored.
 * The same atoms value is accepted again. A different value is refused
 * and the first row stays. There is no erase. Storing a row does not
 * move atoms.
 */
class SwarmFaultEarnedBook {
public:
    bool Keep(const std::string& work, int64_t atoms, std::string& err);
    bool contains(const std::string& work) const;
    int64_t atoms_for(const std::string& work) const;
    std::size_t count() const;

private:
    std::map<std::string, int64_t> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_EARNED_H
