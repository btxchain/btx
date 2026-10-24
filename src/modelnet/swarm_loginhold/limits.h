// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_LIMITS_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmLoginHoldBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmLoginHoldGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmLoginHoldLaunched = false;

/** A stored request is never logged in. */
inline constexpr bool kSwarmLoginHoldLoggedIn = false;

static_assert(kSwarmLoginHoldBytesMoved == 0, "a login hold moves no bytes");
static_assert(!kSwarmLoginHoldGpu, "a login hold does not use a gpu");
static_assert(!kSwarmLoginHoldLaunched, "a login hold does not launch");
static_assert(!kSwarmLoginHoldLoggedIn, "a login hold does not log in");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_LIMITS_H
