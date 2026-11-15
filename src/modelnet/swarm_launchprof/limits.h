// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_LIMITS_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Profile name. Rename does not replace it. */
inline constexpr char kSwarmLaunchProfileName[] = "BTX035-LAUNCH-DECODER-2x64";

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmLaunchProfileBytesMoved = 0;

/** Rename does not touch a GPU. */
inline constexpr bool kSwarmLaunchProfileGpu = false;

/** Rename does not launch work. */
inline constexpr bool kSwarmLaunchProfileLaunched = false;

/** A stored rename does not change the profile. */
inline constexpr bool kSwarmLaunchProfileRenamed = false;

static_assert(kSwarmLaunchProfileName[0] != '\0', "the profile string is non-empty");
static_assert(kSwarmLaunchProfileBytesMoved == 0, "a launch profile rename moves no bytes");
static_assert(!kSwarmLaunchProfileGpu, "a launch profile rename does not use a gpu");
static_assert(!kSwarmLaunchProfileLaunched, "a launch profile rename does not launch");
static_assert(!kSwarmLaunchProfileRenamed, "a launch profile rename does not rename the profile");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_LIMITS_H
