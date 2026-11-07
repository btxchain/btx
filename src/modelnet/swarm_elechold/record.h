// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_RECORD_H

#include <cstdint>

namespace modelnet {

/**
 * The watt-hour count stored by a successful Measure.
 * The record holds watt-hours only. It has no atom count and no charge flag.
 */
struct SwarmElecHoldRecord {
    int64_t watt_hours{0};
};

SwarmElecHoldRecord SwarmElecHoldMakeRecord(int64_t watt_hours);

/** True only when watt_hours is at least 1. */
bool SwarmElecHoldRecordUsable(const SwarmElecHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_RECORD_H
