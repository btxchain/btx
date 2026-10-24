// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. */
inline constexpr std::uint64_t kSwarmEvaluationBytesMoved = 0;

/** This plane moves no atoms. */
inline constexpr std::uint64_t kSwarmEvaluationAtomsMoved = 0;

/** Evaluation does not launch a process. */
inline constexpr bool kSwarmEvaluationLaunched = false;

/** Evaluation does not use a GPU. */
inline constexpr bool kSwarmEvaluationGpu = false;

/** Evaluation does not spend. The text is the zero amount. */
inline constexpr char kSwarmEvaluationAutomaticSpend[] = "0";

/** Evaluation does not broadcast. */
inline constexpr bool kSwarmEvaluationBroadcast = false;

/** A promotion certificate does not promote a realm. */
inline constexpr bool kSwarmEvaluationRealmPromoted = false;

/** A promotion certificate does not admit exact replay. */
inline constexpr bool kSwarmEvaluationExactReplayAdmitted = false;

/** A certificate is not money. */
inline constexpr bool kSwarmEvaluationMoney = false;

static_assert(kSwarmEvaluationBytesMoved == 0, "evaluation moves no bytes");
static_assert(kSwarmEvaluationAtomsMoved == 0, "evaluation moves no atoms");
static_assert(!kSwarmEvaluationLaunched, "evaluation does not launch");
static_assert(!kSwarmEvaluationGpu, "evaluation does not use a gpu");
static_assert(kSwarmEvaluationAutomaticSpend[0] == '0', "spend stays 0");
static_assert(kSwarmEvaluationAutomaticSpend[1] == '\0', "spend stays 0");
static_assert(!kSwarmEvaluationBroadcast, "evaluation does not broadcast");
static_assert(!kSwarmEvaluationRealmPromoted, "evaluation does not promote a realm");
static_assert(!kSwarmEvaluationExactReplayAdmitted, "evaluation does not admit exact replay");
static_assert(!kSwarmEvaluationMoney, "a certificate is not money");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_LIMITS_H
