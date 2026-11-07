// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_METER_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_METER_H

#include <modelnet/swarm_elechold/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Records one watt-hour measurement.
 * watt_hours below 1 is MEASURE and the book stays as it was.
 * A count at least 1 is stored and the call returns true.
 * A second Measure of a count at least 1 is REPLAY and leaves the first
 * watt-hour count. Those checks run in that order. A success clears err.
 * Nothing is charged.
 */
class SwarmElecHoldMeter {
public:
    bool Apply(SwarmElecHoldBook& book, int64_t watt_hours, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_METER_H
