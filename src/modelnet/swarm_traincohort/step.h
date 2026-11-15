// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_STEP_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_STEP_H

#include <modelnet/swarm_traincohort/member.h>

#include <string>

namespace modelnet {

/**
 * One IntegerTrainer::Step on this member, kept only when ReplayMatches
 * accepts the resulting state. A second call after a commit is REPLAY and
 * does not step. The caller has already required a live dataset grant.
 */
bool CohortLocalStep(TrainCohortMember& member, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_STEP_H
