// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_popniche.h>

namespace modelnet {

bool SwarmPopNiche::Place(const std::string& niche, const std::string& id, int64_t quality, std::string& err)
{
    if (niche.empty() || id.empty()) {
        err = "NICHE";
        return false;
    }
    if (quality < 0) {
        err = "RANGE";
        return false;
    }
    const auto it = m_cells.find(niche);
    if (it != m_cells.end() && quality <= it->second.quality) {
        err = "KEPT";
        return false;
    }
    m_cells[niche] = Cell{id, quality};
    err.clear();
    return true;
}

bool SwarmPopNiche::Occupy(const std::string& niche, std::string& id, int64_t& quality) const
{
    const auto it = m_cells.find(niche);
    if (it == m_cells.end()) return false;
    id = it->second.id;
    quality = it->second.quality;
    return true;
}

std::vector<std::string> SwarmPopNiche::Niches() const
{
    std::vector<std::string> names;
    names.reserve(m_cells.size());
    for (const auto& item : m_cells) names.push_back(item.first);
    return names;
}

bool SwarmPopNiche::SingleWinner(std::string& id) const
{
    (void)id;
    return false;
}

} // namespace modelnet
