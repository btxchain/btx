// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_SPEND_POLICY_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_SPEND_POLICY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A research key or a scheduler flag is NOT_SIGNED.
 * Neither flag clears err and returns true.
 * This function does not add atoms, sign, or broadcast.
 */
bool SwarmWorkAcceptPay(bool research_key, bool scheduler, std::string& err);

/** The automatic spend amount. This stays the string "0". */
std::string SwarmWorkAutomaticSpend();

/** Nothing is broadcast. */
bool SwarmWorkBroadcast();

/** Nothing is mined. */
bool SwarmWorkMined();

/** Nothing is sent. This stays 0. */
int64_t SwarmWorkBytesMoved();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_SPEND_POLICY_H
