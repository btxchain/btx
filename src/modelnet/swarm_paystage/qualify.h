// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_QUALIFY_H
#define BTX_MODELNET_SWARM_PAYSTAGE_QUALIFY_H

#include <string>

namespace modelnet {

/**
 * Abort a pay when a hashlock is treated as a qualified multi-hop network.
 * qualified true is UNQUALIFIED. This function does not move atoms.
 * qualified false clears err and returns true.
 */
bool SwarmPayRefuseQualified(bool qualified, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_QUALIFY_H
