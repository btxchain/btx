// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmPrivFamBytesMoved = 0;

/** A private family does not launch a process. */
inline constexpr bool kSwarmPrivFamLaunched = false;

/** Nothing on this plane connects. */
inline constexpr bool kSwarmPrivFamConnected = false;

/** A private family stays unpublished. */
inline constexpr bool kSwarmPrivFamPublished = false;

/** DNS seeds are not retained. */
inline constexpr int64_t kSwarmPrivFamSeedCount = 0;

static_assert(kSwarmPrivFamBytesMoved == 0, "private family moves no bytes");
static_assert(!kSwarmPrivFamLaunched, "private family does not launch");
static_assert(!kSwarmPrivFamConnected, "private family does not connect");
static_assert(!kSwarmPrivFamPublished, "private family is not published");
static_assert(kSwarmPrivFamSeedCount == 0, "private family keeps no DNS seeds");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_LIMITS_H
