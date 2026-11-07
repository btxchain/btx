// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_REMOTE_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_REMOTE_H

#include <modelnet/swarm_traincohort/member.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * remote_step at or behind the local step is STALE and leaves the local hash.
 * remote_step == local + 1 is stored as pending only. A larger gap is GAP
 * and stores nothing.
 */
bool CohortOfferRemote(TrainCohortMember& member, uint64_t remote_step, const std::string& hash, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_REMOTE_H
