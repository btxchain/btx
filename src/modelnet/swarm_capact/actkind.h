// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_ACTKIND_H
#define BITCOIN_MODELNET_SWARM_CAPACT_ACTKIND_H

#include <modelnet/swarm_capact/actions.h>
#include <modelnet/swarm_capact/grants.h>

#include <string>

namespace modelnet {

/**
 * How an Act relates to the grant set and the action log.
 * Ready is the only result that may be recorded. The other results
 * record nothing.
 */
enum class SwarmCapActActKind {
    Ready,
    Capability,
    NotActed,
    Replay,
};

/**
 * Classify one Act attempt.
 * An empty name is Capability. A name that was not granted is NotActed.
 * A name already recorded is Replay. This does not modify either set.
 */
SwarmCapActActKind SwarmCapActClassifyAct(const SwarmCapActGrants& grants,
                                           const SwarmCapActActions& actions,
                                           const std::string& name);

/**
 * Refusal code for a non-ready act, or nullptr for Ready.
 */
const char* SwarmCapActActKindCode(SwarmCapActActKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_ACTKIND_H
