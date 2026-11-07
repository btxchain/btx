// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_PAGE_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_PAGE_H

#include <string>

namespace modelnet {

/**
 * How one page name stands on its own, before any roster is consulted.
 * Named is the only result that may be stored. Empty stores nothing.
 */
enum class SwarmCachePairPageKind {
    Empty,
    Named,
};

/** An empty page is Empty. Any other page is Named. */
SwarmCachePairPageKind SwarmCachePairClassifyPage(const std::string& page);

/**
 * Refusal code for an empty page, or nullptr when the page is named.
 * The code is PAGE.
 */
const char* SwarmCachePairPageCode(SwarmCachePairPageKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_PAGE_H
