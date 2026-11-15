// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_LIMITS_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_LIMITS_H

#include <cstdint>

namespace modelnet {

/** The only preimage length this book stores. */
inline constexpr int64_t kSwarmSigCoverPreimageLen = 32;

/** Inspector value when no 32-byte preimage description is stored. */
inline constexpr int kSwarmSigCoverPreimageAbsent = -1;

/** A covering sighash description is not a signature. */
inline constexpr bool kSwarmSigCoverSignedOk = false;

/** This plane does not raise a secp penalty. */
inline constexpr bool kSwarmSigCoverSecpPenalty = false;

/** This plane does not broadcast. */
inline constexpr bool kSwarmSigCoverBroadcast = false;

/** This plane does not launch work. */
inline constexpr bool kSwarmSigCoverLaunched = false;

/** This plane does not use a gpu. */
inline constexpr bool kSwarmSigCoverGpu = false;

/** This plane moves no atoms. */
inline constexpr int64_t kSwarmSigCoverAtomsMoved = 0;

/** Automatic spend stays the string "0". */
inline constexpr char kSwarmSigCoverAutomaticSpend[] = "0";

static_assert(kSwarmSigCoverPreimageLen == 32, "preimage length is 32");
static_assert(kSwarmSigCoverPreimageAbsent == -1, "absent preimage is -1");
static_assert(kSwarmSigCoverPreimageLen != static_cast<int64_t>(kSwarmSigCoverPreimageAbsent),
              "stored length differs from absent");
static_assert(kSwarmSigCoverPreimageLen <= 2147483647, "preimage length fits in int");
static_assert(!kSwarmSigCoverSignedOk, "signed_ok stays false");
static_assert(!kSwarmSigCoverSecpPenalty, "secp penalty stays false");
static_assert(!kSwarmSigCoverBroadcast, "broadcast stays false");
static_assert(!kSwarmSigCoverLaunched, "launched stays false");
static_assert(!kSwarmSigCoverGpu, "gpu stays false");
static_assert(kSwarmSigCoverAtomsMoved == 0, "atoms moved stay 0");
static_assert(kSwarmSigCoverAutomaticSpend[0] == '0', "automatic spend stays 0");
static_assert(kSwarmSigCoverAutomaticSpend[1] == '\0', "automatic spend is the string 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_LIMITS_H
