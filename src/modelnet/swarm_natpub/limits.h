// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NATPUB_LIMITS_H
#define BITCOIN_MODELNET_SWARM_NATPUB_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A claimed endpoint is not a payload. */
inline constexpr int64_t kSwarmNatPubBytesMoved = 0;

/** Claim does not launch work. */
inline constexpr bool kSwarmNatPubLaunched = false;

/** A claimed endpoint does not connect. */
inline constexpr bool kSwarmNatPubConnected = false;

/** A claimed endpoint stays unpublished. */
inline constexpr bool kSwarmNatPubPublished = false;

/** The DNS seed list stays empty. */
inline constexpr int64_t kSwarmNatPubSeedCount = 0;

static_assert(kSwarmNatPubBytesMoved == 0, "a nat publish claim moves no bytes");
static_assert(!kSwarmNatPubLaunched, "a nat publish claim does not launch");
static_assert(!kSwarmNatPubConnected, "a nat publish claim does not connect");
static_assert(!kSwarmNatPubPublished, "a nat publish claim is not published");
static_assert(kSwarmNatPubSeedCount == 0, "a nat publish claim keeps no DNS seeds");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NATPUB_LIMITS_H
