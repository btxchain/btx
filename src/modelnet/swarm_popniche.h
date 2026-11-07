// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_POPNICHE_H
#define BTX_MODELNET_SWARM_POPNICHE_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Quality-diversity map. Each niche keeps its best occupant. A worse score
 * does not replace it. Niches are not collapsed into one winner.
 */
class SwarmPopNiche {
public:
    bool Place(const std::string& niche, const std::string& id, int64_t quality, std::string& err);
    bool Occupy(const std::string& niche, std::string& id, int64_t& quality) const;
    std::vector<std::string> Niches() const;
    bool SingleWinner(std::string& id) const;

private:
    struct Cell {
        std::string id;
        int64_t quality{0};
    };
    std::map<std::string, Cell> m_cells;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_POPNICHE_H
