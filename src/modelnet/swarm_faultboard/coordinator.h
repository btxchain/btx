// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_COORDINATOR_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_COORDINATOR_H

#include <modelnet/swarm_faultboard/claim.h>
#include <modelnet/swarm_faultboard/earned.h>
#include <modelnet/swarm_faultboard/epoch.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Coordinator loss, epoch replacement, stale resume, and permanent loss.
 * None of these delete a claim or an earned row.
 */
bool SwarmFaultCoordinatorGone(const SwarmFaultClaimBook& claims, std::string& err);
bool SwarmFaultReplaceCoordinator(SwarmFaultEpoch& epoch, int64_t old_epoch, int64_t new_epoch, std::string& err);
bool SwarmFaultResumeStale(int64_t epoch, int64_t current, std::string& err);
bool SwarmFaultPermanentGone(const SwarmFaultClaimBook& claims, const SwarmFaultEarnedBook& earned, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_COORDINATOR_H
