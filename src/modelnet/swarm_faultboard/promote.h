// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_PROMOTE_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_PROMOTE_H

#include <modelnet/swarm_faultboard/head.h>
#include <modelnet/swarm_faultboard/quiet.h>

#include <string>

namespace modelnet {

/**
 * Interrupted promotion, canary regression, and conflicting reports.
 * Promotion does not change the active head. An empty previous head does
 * not append a rollback. Conflicting reports are not averaged.
 */
bool SwarmFaultPromotionInterrupted(const SwarmFaultHeadBook& heads, const std::string& channel, std::string& err);
bool SwarmFaultCanaryRegress(SwarmFaultHeadBook& heads, const std::string& channel, const std::string& previous, std::string& err);
bool SwarmFaultConflictingReports(const SwarmFaultQuiet& quiet, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_PROMOTE_H
