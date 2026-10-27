// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYREG_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PAYREG_LIMITS_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/** Payment hash size Build will pass to the claim leaf. Any other size is PREIMAGE. */
inline constexpr std::size_t kSwarmPayRegHashSize = 32;

/** Refund timeout Build will pass to the refund leaf. Any other value is TIMEOUT. */
inline constexpr int64_t kSwarmPayRegRefundTimeout = 160;

/** launched() stays this value. Nothing is spawned. */
inline constexpr bool kSwarmPayRegLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmPayRegGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmPayRegBroadcast = false;

/** qualified() stays this value. Settlement stays refused. */
inline constexpr bool kSwarmPayRegQualified = false;

/** spendable() stays this value. Collateral is not advertised as spendable money. */
inline constexpr bool kSwarmPayRegSpendable = false;

/** mainnet() stays this value. This register does not select mainnet. */
inline constexpr bool kSwarmPayRegMainnet = false;

/** atoms_moved() stays this value. No atoms move. */
inline constexpr int64_t kSwarmPayRegAtomsMoved = 0;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmPayRegAutomaticSpend[] = "0";

static_assert(kSwarmPayRegHashSize == 32, "payment hash is 32 bytes");
static_assert(kSwarmPayRegRefundTimeout == 160, "refund timeout pin is 160");
static_assert(!kSwarmPayRegLaunched, "this register does not launch");
static_assert(!kSwarmPayRegGpu, "this register does not use a gpu");
static_assert(!kSwarmPayRegBroadcast, "this register does not broadcast");
static_assert(!kSwarmPayRegQualified, "this register does not qualify settlement");
static_assert(!kSwarmPayRegSpendable, "this register does not advertise spendable money");
static_assert(!kSwarmPayRegMainnet, "this register does not select mainnet");
static_assert(kSwarmPayRegAtomsMoved == 0, "atoms moved stays 0");
static_assert(kSwarmPayRegAutomaticSpend[0] == '0' && kSwarmPayRegAutomaticSpend[1] == '\0',
              "automatic spend stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYREG_LIMITS_H
