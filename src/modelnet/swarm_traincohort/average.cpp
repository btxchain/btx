// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_traincohort/average.h>

#include <modelnet/swarm_traincohort/error.h>

namespace modelnet {

bool CohortAverage(std::string& err)
{
    err = COHORT_NOT_AVERAGED;
    return false;
}

} // namespace modelnet
