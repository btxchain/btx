// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_CODES_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_CODES_H

namespace modelnet {

/** page is empty, or Share names a page that was never stored. Nothing is stored. */
inline constexpr char kSwarmCachePairPage[] = "PAGE";

/** member is empty. Nothing is stored. */
inline constexpr char kSwarmCachePairMember[] = "MEMBER";

/**
 * The same page and member are already placed, or this page was
 * already shared. The first placement and the first share stay.
 */
inline constexpr char kSwarmCachePairReplay[] = "REPLAY";

/**
 * The page has fewer than two distinct members.
 * Share records nothing.
 */
inline constexpr char kSwarmCachePairAlone[] = "ALONE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_CODES_H
