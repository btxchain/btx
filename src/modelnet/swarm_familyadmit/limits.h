// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmFamilyAdmitBytesMoved = 0;

/** Admission does not launch a process. */
inline constexpr bool kSwarmFamilyAdmitLaunched = false;

/** Discovery does not connect. */
inline constexpr bool kSwarmFamilyAdmitConnected = false;

/** DNS seeds are not retained. */
inline constexpr int64_t kSwarmFamilyAdmitSeedCount = 0;

static_assert(kSwarmFamilyAdmitBytesMoved == 0, "family admission moves no bytes");
static_assert(!kSwarmFamilyAdmitLaunched, "family admission does not launch");
static_assert(!kSwarmFamilyAdmitConnected, "discovery does not connect");
static_assert(kSwarmFamilyAdmitSeedCount == 0, "family admission keeps no DNS seeds");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_LIMITS_H
