// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_MEMBER_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_MEMBER_H

#include <string>

namespace modelnet {

/**
 * How one member name stands on its own, before any roster is consulted.
 * Named is the only result that may be stored. Empty stores nothing.
 */
enum class SwarmCachePairMemberKind {
    Empty,
    Named,
};

/** An empty member is Empty. Any other member is Named. */
SwarmCachePairMemberKind SwarmCachePairClassifyMember(const std::string& member);

/**
 * Refusal code for an empty member, or nullptr when the member is named.
 * The code is MEMBER.
 */
const char* SwarmCachePairMemberCode(SwarmCachePairMemberKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_MEMBER_H
