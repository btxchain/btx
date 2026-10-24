// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Parentage text is not trust. */
inline constexpr bool kSwarmParentageTrusted = false;

/** A stored license is not realm promotion. Quality is not realm promotion. */
inline constexpr bool kSwarmParentageRealmPromoted = false;

/** A stored license is not ExactReplay admission. */
inline constexpr bool kSwarmParentageExactReplayAdmitted = false;

/** This plane does not launch work. */
inline constexpr bool kSwarmParentageLaunched = false;

/** This plane does not use a gpu. */
inline constexpr bool kSwarmParentageGpu = false;

/** This plane moves no bytes. */
inline constexpr int64_t kSwarmParentageBytesMoved = 0;

/** A binding records parent, recipe, dataset, and license. */
inline constexpr int kSwarmParentageFieldCount = 4;

static_assert(!kSwarmParentageTrusted, "trusted stays false");
static_assert(!kSwarmParentageRealmPromoted, "realm promoted stays false");
static_assert(!kSwarmParentageExactReplayAdmitted, "exact replay admitted stays false");
static_assert(!kSwarmParentageLaunched, "launched stays false");
static_assert(!kSwarmParentageGpu, "gpu stays false");
static_assert(kSwarmParentageBytesMoved == 0, "bytes moved stay 0");
static_assert(kSwarmParentageFieldCount == 4, "four parentage fields");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_LIMITS_H
