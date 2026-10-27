// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmGuestHoldBytesMoved = 0;

/** Check does not touch a GPU. */
inline constexpr bool kSwarmGuestHoldGpu = false;

/** Check does not launch work. */
inline constexpr bool kSwarmGuestHoldLaunched = false;

/** A stored check is never passed. */
inline constexpr bool kSwarmGuestHoldPassed = false;

/** A stored check never logs in. */
inline constexpr bool kSwarmGuestHoldLoggedIn = false;

static_assert(kSwarmGuestHoldBytesMoved == 0, "a guest-agent hold moves no bytes");
static_assert(!kSwarmGuestHoldGpu, "a guest-agent hold does not use a gpu");
static_assert(!kSwarmGuestHoldLaunched, "a guest-agent hold does not launch");
static_assert(!kSwarmGuestHoldPassed, "a guest-agent hold does not pass");
static_assert(!kSwarmGuestHoldLoggedIn, "a guest-agent hold does not log in");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_LIMITS_H
