// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_AVERAGE_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_AVERAGE_H

#include <string>

namespace modelnet {

/** Always NOT_AVERAGED. This function has no member state to change. */
bool CohortAverage(std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_AVERAGE_H
