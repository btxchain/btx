// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_METERDRAIN_H
#define BTX_MODELNET_SWARM_METERDRAIN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A metered-link record. node_id names the node. metered is whether the
 * link is metered. want_run asks this record to hold a run request.
 *
 * A metered link drains workers to zero. A run request is held.
 */
struct SwarmMeterDrain {
    std::string node_id;
    bool metered{false};
    bool want_run{false};
};

/**
 * Outcome of noting a metered-link drain. workers stays 0 on every path.
 * A metered link drains workers to zero.
 */
struct SwarmMeterDrainResult {
    std::string code;
    int64_t workers{0};
};

/**
 * Note a metered-link drain. Order, first match wins: an empty node_id is
 * NODE. metered true is DRAINED even when want_run is false. want_run is
 * HELD. Otherwise the note is NOTED and err is clear. A metered link
 * drains workers to zero. workers stays 0 on every path.
 */
SwarmMeterDrainResult SwarmNoteMeterDrain(const SwarmMeterDrain& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_METERDRAIN_H
