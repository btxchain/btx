// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_GRANTKIND_H
#define BITCOIN_MODELNET_SWARM_CAPACT_GRANTKIND_H

#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * How a Grant relates to names already stored.
 * Ready is the only result that may be stored. The other results store nothing.
 */
enum class SwarmCapActGrantKind {
    Ready,
    Capability,
    Replay,
};

/**
 * Classify one Grant attempt.
 * An empty name is Capability. A name already granted is Replay.
 * This does not modify the grant set.
 */
SwarmCapActGrantKind SwarmCapActClassifyGrant(const SwarmCapActGrants& grants, const std::string& name);

/**
 * Refusal code for a non-ready grant, or nullptr for Ready.
 */
const char* SwarmCapActGrantKindCode(SwarmCapActGrantKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_GRANTKIND_H
