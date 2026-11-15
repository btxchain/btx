// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_RECORD_H

#include <cstdint>

namespace modelnet {

/**
 * The joule count stored by a successful Measure.
 * The record holds joules only. It has no atom count and no charge flag.
 */
struct SwarmWearHoldRecord {
    int64_t joules{0};
};

SwarmWearHoldRecord SwarmWearHoldMakeRecord(int64_t joules);

/** True only when joules is at least 1. */
bool SwarmWearHoldRecordUsable(const SwarmWearHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_RECORD_H
