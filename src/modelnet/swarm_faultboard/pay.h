// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_PAY_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_PAY_H

#include <modelnet/swarm_faultboard/earned.h>
#include <modelnet/swarm_faultboard/quiet.h>

#include <string>

namespace modelnet {

/**
 * Payment crash after earn, and a mature refund.
 * An earned row is kept and a missing row is not created.
 * atoms_moved() stays 0. broadcast() stays false.
 */
bool SwarmFaultPayCrash(const SwarmFaultEarnedBook& earned, const SwarmFaultQuiet& quiet, const std::string& work, std::string& err);
bool SwarmFaultRefundMature(const SwarmFaultQuiet& quiet, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_PAY_H
