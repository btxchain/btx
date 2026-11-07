// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_UNDER_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_UNDER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * watt_hours below 1 is MEASURE. The caller stores nothing.
 * A value of 1 or more is not this refusal.
 */
class SwarmElecHoldUnder {
public:
    bool accept(int64_t watt_hours, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_UNDER_H
