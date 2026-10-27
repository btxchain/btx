// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Per-hop close margin. Required slack is hop_count times this value. */
inline constexpr int64_t kSwarmRouteBookMargin = 160;

/** Hashlock preimage length that still does not settle a route. */
inline constexpr int64_t kSwarmRouteBookPreimageLen = 32;

/** This plane does not qualify a route. */
inline constexpr bool kSwarmRouteBookQualified = false;

/** This plane does not raise a secp penalty. */
inline constexpr bool kSwarmRouteBookSecpPenalty = false;

/** This plane does not broadcast. */
inline constexpr bool kSwarmRouteBookBroadcast = false;

/** This plane does not launch work. */
inline constexpr bool kSwarmRouteBookLaunched = false;

/** This plane does not use a gpu. */
inline constexpr bool kSwarmRouteBookGpu = false;

/** This plane moves no atoms. */
inline constexpr int64_t kSwarmRouteBookAtomsMoved = 0;

/** Automatic spend stays the string "0". */
inline constexpr char kSwarmRouteBookAutomaticSpend[] = "0";

/** A covering sighash description is not a signature. */
inline constexpr bool kSwarmRouteBookSignedOk = false;

static_assert(kSwarmRouteBookMargin == 160, "close margin is 160");
static_assert(kSwarmRouteBookMargin > 0, "close margin is positive");
static_assert(kSwarmRouteBookMargin * 0 == 0, "zero hops require 0");
static_assert(kSwarmRouteBookMargin * 2 == 320, "two hops require 320");
static_assert(kSwarmRouteBookMargin * 3 == 480, "three hops require 480");
static_assert(kSwarmRouteBookPreimageLen == 32, "hashlock preimage length is 32");
static_assert(!kSwarmRouteBookQualified, "qualified stays false");
static_assert(!kSwarmRouteBookSecpPenalty, "secp penalty stays false");
static_assert(!kSwarmRouteBookBroadcast, "broadcast stays false");
static_assert(!kSwarmRouteBookLaunched, "launched stays false");
static_assert(!kSwarmRouteBookGpu, "gpu stays false");
static_assert(kSwarmRouteBookAtomsMoved == 0, "atoms moved stay 0");
static_assert(!kSwarmRouteBookSignedOk, "signed_ok stays false");
static_assert(kSwarmRouteBookAutomaticSpend[0] == '0', "automatic spend stays 0");
static_assert(kSwarmRouteBookAutomaticSpend[1] == '\0', "automatic spend is the string 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_LIMITS_H
