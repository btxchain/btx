// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBATTERYDRAIN2_H
#define BTX_MODELNET_SWARM_NOTNOBATTERYDRAIN2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local refusal note. governor_id names the governor. battery is whether
 * the host is on battery. want_keep asks this note to hold workers.
 *
 * On battery the governor drains workers to zero. Nothing broadcasts,
 * spends, launches, mines, or moves bytes.
 */
struct SwarmNotNoBatteryDrain2 {
    std::string governor_id;
    bool battery{false};
    bool want_keep{false};
};

/**
 * Outcome of noting a battery governor. workers stays 0 on every path.
 * On battery the governor drains workers to zero.
 */
struct SwarmNotNoBatteryDrain2Result {
    std::string code;
    int64_t workers{0};
};

/**
 * Note a battery governor without keeping workers. Order, first match wins:
 * an empty governor_id is GOVERNOR. battery true is DRAINED even when
 * want_keep is false. want_keep is HELD. Otherwise the note is NOTED and
 * err is clear. On battery the governor drains workers to zero. workers
 * stays 0 on every path.
 */
SwarmNotNoBatteryDrain2Result SwarmNoteNotNoBatteryDrain2(const SwarmNotNoBatteryDrain2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBATTERYDRAIN2_H
