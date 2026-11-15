// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Atom count of every quote. A fiat quote credits nothing. */
inline constexpr int64_t kSwarmQuoteFiatAtoms = 0;

/** A stored usd is a quote. It is never a BTX balance. */
inline constexpr bool kSwarmQuoteFiatUsdIsBalance = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmQuoteFiatBytesMoved = 0;

/** Quote does not broadcast. */
inline constexpr bool kSwarmQuoteFiatBroadcast = false;

/** This plane does not mine. */
inline constexpr bool kSwarmQuoteFiatMined = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmQuoteFiatAutomaticSpend[] = "0";

static_assert(kSwarmQuoteFiatAtoms == 0, "a fiat quote carries no atoms");
static_assert(!kSwarmQuoteFiatUsdIsBalance, "a fiat quote is not a balance");
static_assert(kSwarmQuoteFiatBytesMoved == 0, "a fiat quote moves no bytes");
static_assert(!kSwarmQuoteFiatBroadcast, "a fiat quote does not broadcast");
static_assert(!kSwarmQuoteFiatMined, "a fiat quote does not mine");
static_assert(kSwarmQuoteFiatAutomaticSpend[0] == '0' && kSwarmQuoteFiatAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_LIMITS_H
