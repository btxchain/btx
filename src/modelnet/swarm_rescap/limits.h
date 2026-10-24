// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_LIMITS_H
#define BITCOIN_MODELNET_SWARM_RESCAP_LIMITS_H

#include <cstdint>

namespace modelnet {

/** threads below this is CAP and is not stored. */
inline constexpr int64_t kSwarmResCapMinThreads = 1;

/** The thread cap. cap_threads() stays this value. 64 itself may be stored. */
inline constexpr int64_t kSwarmResCapThreadCap = 64;

/** stored_threads() when Raise has stored nothing for that count. */
inline constexpr int64_t kSwarmResCapUnset = 0;

/** This plane moves no bytes. A stored thread count is not a payload. */
inline constexpr int64_t kSwarmResCapBytesMoved = 0;

/** Raise does not touch a GPU. */
inline constexpr bool kSwarmResCapGpu = false;

/** Raise does not launch work. */
inline constexpr bool kSwarmResCapLaunched = false;

/** A stored thread count is never raised. */
inline constexpr bool kSwarmResCapRaised = false;

static_assert(kSwarmResCapMinThreads == 1, "a stored thread count is at least 1");
static_assert(kSwarmResCapThreadCap == 64, "the thread cap stays 64");
static_assert(kSwarmResCapMinThreads <= kSwarmResCapThreadCap, "the floor sits within the cap");
static_assert(kSwarmResCapUnset == 0, "an empty plane stores no thread count");
static_assert(kSwarmResCapUnset < kSwarmResCapMinThreads, "an empty count is below a stored count");
static_assert(kSwarmResCapBytesMoved == 0, "a thread cap record moves no bytes");
static_assert(!kSwarmResCapGpu, "a thread cap record does not use a gpu");
static_assert(!kSwarmResCapLaunched, "a thread cap record does not launch");
static_assert(!kSwarmResCapRaised, "a thread cap record is not raised");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_LIMITS_H
