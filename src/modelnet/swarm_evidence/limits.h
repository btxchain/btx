// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVIDENCE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_EVIDENCE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** launched() stays this value. Nothing is started. */
inline constexpr bool kSwarmEvidenceLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmEvidenceGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmEvidenceBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmEvidenceAutomaticSpend[] = "0";

/** bytes_moved() stays this value. A promise moves no bytes. */
inline constexpr int64_t kSwarmEvidenceBytesMoved = 0;

static_assert(!kSwarmEvidenceLaunched, "this record does not launch");
static_assert(!kSwarmEvidenceGpu, "this record does not use a gpu");
static_assert(!kSwarmEvidenceBroadcast, "this record does not broadcast");
static_assert(kSwarmEvidenceAutomaticSpend[0] == '0' && kSwarmEvidenceAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmEvidenceBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVIDENCE_LIMITS_H
