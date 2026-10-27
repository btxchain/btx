// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTSAVE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CKPTSAVE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded name is not a payload. */
inline constexpr int64_t kSwarmCkptSaveBytesMoved = 0;

/** Request does not touch a GPU. */
inline constexpr bool kSwarmCkptSaveGpu = false;

/** Request does not launch work. */
inline constexpr bool kSwarmCkptSaveLaunched = false;

/** A stored request is never saved. */
inline constexpr bool kSwarmCkptSaveSaved = false;

static_assert(kSwarmCkptSaveBytesMoved == 0, "a checkpoint save hold moves no bytes");
static_assert(!kSwarmCkptSaveGpu, "a checkpoint save hold does not use a gpu");
static_assert(!kSwarmCkptSaveLaunched, "a checkpoint save hold does not launch");
static_assert(!kSwarmCkptSaveSaved, "a checkpoint save hold does not save");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTSAVE_LIMITS_H
