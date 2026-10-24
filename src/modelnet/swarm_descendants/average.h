// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_AVERAGE_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_AVERAGE_H

#include <string>

namespace modelnet {

/**
 * Refuse to average two branches.
 * Asks SwarmLineage::Average, which answers NOT_AVERAGED, then returns
 * the same refusal. The caller does not write either answer onto a head.
 */
bool RefuseDescendantAverage(const std::string& left, const std::string& right, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_AVERAGE_H
