// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_SNAPSHOT_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_SNAPSHOT_H

#include <modelnet/swarm_paymesh.h>

#include <cstdint>

namespace modelnet {

/**
 * Call SwarmReorgExit on a snapshot of this plane.
 * The call matches when the result is frozen and every other field is unchanged,
 * including earned_atoms. out receives the helper result either way.
 */
bool ReorgHoldReorgMatches(int64_t earned, int channel_sequence, SwarmRecoverySnapshot& out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_SNAPSHOT_H
