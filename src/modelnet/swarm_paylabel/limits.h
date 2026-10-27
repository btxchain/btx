// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_LIMITS_H

#include <cstdint>

namespace modelnet {

/** The only label Accept will store. The match is exact. */
inline constexpr char kSwarmPayLabelWork[] = "work-payment";

/** Refused exactly. This label is never stored. */
inline constexpr char kSwarmPayLabelProfit[] = "profit-share";

/** atoms() stays this value. Accepting a label does not credit atoms. */
inline constexpr int64_t kSwarmPayLabelAtoms = 0;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmPayLabelBytesMoved = 0;

/** Accept does not broadcast. */
inline constexpr bool kSwarmPayLabelBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmPayLabelAutomaticSpend[] = "0";

static_assert(kSwarmPayLabelAtoms == 0, "payment label spends no atoms");
static_assert(kSwarmPayLabelBytesMoved == 0, "payment label moves no bytes");
static_assert(!kSwarmPayLabelBroadcast, "payment label does not broadcast");
static_assert(kSwarmPayLabelAutomaticSpend[0] == '0' && kSwarmPayLabelAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(sizeof(kSwarmPayLabelWork) == sizeof("work-payment"), "work-payment spelling");
static_assert(sizeof(kSwarmPayLabelProfit) == sizeof("profit-share"), "profit-share spelling");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_LIMITS_H
