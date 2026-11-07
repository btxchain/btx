// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_SPEND_POLICY_H
#define BTX_MODELNET_SWARM_PAYSTAGE_SPEND_POLICY_H

#include <string>

namespace modelnet {

/**
 * A research key or a scheduler flag is NOT_SIGNED.
 * Neither flag clears err and returns true.
 * This function does not move atoms, sign, or broadcast.
 */
bool SwarmPayAcceptSpend(bool research_key, bool scheduler, std::string& err);

/** The automatic spend amount. This stays the string "0". */
std::string SwarmPayAutomaticSpend();

/** Nothing is broadcast. */
bool SwarmPayBroadcast();

/** Nothing is mined. */
bool SwarmPayMined();

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_SPEND_POLICY_H
