// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_ROSTER_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_ROSTER_H

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Placements stored by a successful Place, keyed by page.
 * place refuses an empty page, an empty member, and a page/member
 * pair already present. A refused place leaves the first placement
 * in place. There is no erase. Sharing is not recorded here.
 */
class SwarmCachePairRoster {
public:
    bool known(const std::string& page) const;
    bool contains(const std::string& page, const std::string& member) const;
    std::size_t members(const std::string& page) const;
    std::size_t pages() const;

    /** Distinct members on page, in sorted order. Empty when unknown. */
    std::vector<std::string> list(const std::string& page) const;

    /**
     * Store member on page.
     * Refuses an unusable seat and a duplicate pair. On refusal the
     * roster is unchanged.
     */
    bool place(const std::string& page, const std::string& member);

private:
    std::map<std::string, std::set<std::string>> m_pages;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_ROSTER_H
