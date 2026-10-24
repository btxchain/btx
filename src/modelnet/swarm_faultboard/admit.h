// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_ADMIT_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_ADMIT_H

#include <modelnet/swarm_faultboard/quiet.h>

#include <string>

namespace modelnet {

/**
 * Dataset withdrawal and a false compatibility claim.
 * running() stays false. admitted() stays false.
 */
bool SwarmFaultDatasetWithdrawn(const SwarmFaultQuiet& quiet, std::string& err);
bool SwarmFaultFalseCompat(const SwarmFaultQuiet& quiet, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_ADMIT_H
