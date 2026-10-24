// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_WARM_H
#define BITCOIN_MODELNET_SWARM_READFENCE_WARM_H

#include <cstddef>
#include <set>
#include <string>

namespace modelnet {

/**
 * Page ids recorded by Prefetch.
 * Note stores the page id it is given, including an empty id.
 * A second note of the same id stays one record.
 * Noting an id moves no bytes and allocates no CUDA buffer.
 */
class SwarmReadWarm {
public:
    bool noted(const std::string& page) const;
    std::size_t size() const;

    bool Note(const std::string& page);

private:
    std::set<std::string> m_pages;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_WARM_H
