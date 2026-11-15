// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_PREIMAGE_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_PREIMAGE_H

#include <modelnet/swarm_sigcover/types.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Plan a preimage length description.
 * length other than 32 is PREIMAGE. The plan writes nothing, so a stored 32 stays.
 * A second length of 32 is REPLAY. The plan writes nothing.
 * The first length of 32 accepts a one-way preimage mark.
 * The mark does not make a claim succeed and does not cover outputs by itself.
 */
SwarmSigCoverPlan SwarmSigCoverPlanPreimage(bool preimage_described, int64_t length, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_PREIMAGE_H
