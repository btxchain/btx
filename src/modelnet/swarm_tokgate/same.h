// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_SAME_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_SAME_H

#include <string>

namespace modelnet {

/**
 * True when left and right are the same bytes.
 * The compare does not trim and does not fold case.
 */
bool SwarmTokenGateSame(const std::string& left, const std::string& right);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_SAME_H
