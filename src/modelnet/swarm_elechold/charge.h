// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_CHARGE_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_CHARGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A watt-hour measurement is not a BTX charge.
 * Apply sets err to HELD and returns false for every atoms value,
 * including atoms below 1. atoms is discarded.
 * There is no method that stores watt-hours, marks a charge, or adds atoms.
 */
class SwarmElecHoldCharge {
public:
    bool Apply(int64_t atoms, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_CHARGE_H
