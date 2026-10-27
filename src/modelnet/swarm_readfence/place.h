// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_PLACE_H
#define BITCOIN_MODELNET_SWARM_READFENCE_PLACE_H

#include <modelnet/swarm_readfence/book.h>

#include <string>

namespace modelnet {

/**
 * Places a page in a family.
 * An empty page or an empty family is PAGE and the book is unchanged.
 * A later non-empty family for the same page replaces that family only.
 * Place does not move bytes.
 */
class SwarmReadPlace {
public:
    bool Apply(SwarmReadBook& book, const std::string& page, const std::string& family, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_PLACE_H
