// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_BOOK_H
#define BITCOIN_MODELNET_SWARM_READFENCE_BOOK_H

#include <modelnet/swarm_readfence/page.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Placed pages. Place stores a non-empty page with a non-empty family.
 * A later Place of the same page replaces the family only.
 * An empty page or an empty family leaves the book unchanged.
 * This book moves no bytes.
 */
class SwarmReadBook {
public:
    bool placed(const std::string& page) const;
    std::string family(const std::string& page) const;
    std::size_t size() const;

    bool Place(const std::string& page, const std::string& family);

private:
    std::map<std::string, SwarmReadPage> m_pages;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_BOOK_H
