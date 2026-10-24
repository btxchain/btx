// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_FUND_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_FUND_H

#include <modelnet/swarm_onechannel/record.h>

#include <string>

namespace modelnet {

/**
 * Decide whether pool may be marked funded.
 * A null pool sets err to POOL and leaves mark_funded false.
 * refund_bound false sets err to FUNDING and leaves mark_funded false.
 * refund_bound true sets mark_funded and clears err.
 * The decision does not broadcast and does not move atoms.
 */
bool SwarmOneChannelDecideFund(const SwarmOneChannelPool* existing,
                               bool refund_bound,
                               bool& mark_funded,
                               std::string& err);

/**
 * Mark row funded and holding money.
 * Atoms stay at zero. The stored quote is left as it was.
 * Other pools are not visible here, so they cannot change.
 * This does not broadcast.
 */
void SwarmOneChannelApplyFund(SwarmOneChannelPool& row);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_FUND_H
