// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_ERROR_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_ERROR_H

namespace modelnet {

inline constexpr char COHORT_MEMBER[] = "MEMBER";
inline constexpr char COHORT_REPLAY[] = "REPLAY";
inline constexpr char COHORT_DATASET[] = "DATASET";
inline constexpr char COHORT_STALE[] = "STALE";
inline constexpr char COHORT_GAP[] = "GAP";
inline constexpr char COHORT_NOT_AVERAGED[] = "NOT_AVERAGED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_ERROR_H
