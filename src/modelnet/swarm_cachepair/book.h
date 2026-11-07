// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_BOOK_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_BOOK_H

#include <modelnet/swarm_cachepair/record.h>

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Shares stored by a successful Share, keyed by page.
 * store refuses an unusable record and a page already present.
 * A refused store leaves the first record in place. There is no
 * erase and no method that rewrites a stored member list.
 */
class SwarmCachePairBook {
public:
    bool contains(const std::string& page) const;
    std::size_t size() const;
    std::vector<std::string> members_of(const std::string& page) const;

    /**
     * Store one share for page.
     * Refuses an unusable record and a duplicate page. On refusal
     * the book is unchanged.
     */
    bool store(const std::string& page, const std::vector<std::string>& members);

private:
    std::map<std::string, SwarmCachePairRecord> m_shares;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_BOOK_H
