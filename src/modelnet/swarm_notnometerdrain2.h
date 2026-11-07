// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMETERDRAIN2_H
#define BTX_MODELNET_SWARM_NOTNOMETERDRAIN2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one governor. metered records a metered link.
 * want_keep asks this note to keep workers running.
 *
 * On a metered link the governor drains workers to zero. workers stays
 * 0 on every path. Nothing broadcasts, spends, launches, mines, or
 * moves bytes.
 */
struct SwarmNotNoMeterDrain2 {
    std::string governor_id;
    bool metered{false};
    bool want_keep{false};
};

/**
 * Outcome of noting a metered-link drain. workers stays 0 on every path.
 * On a metered link the governor drains workers to zero.
 */
struct SwarmNotNoMeterDrain2Result {
    std::string code;
    int64_t workers{0};
};

/**
 * Note a metered link without keeping workers running.
 * Order, first match wins: an empty governor_id is GOVERNOR. If metered
 * is true, the note is DRAINED even when want_keep is false. want_keep
 * is HELD. Otherwise the note is NOTED and err is cleared. workers
 * stays 0 on every path. On a metered link the governor drains workers
 * to zero.
 */
SwarmNotNoMeterDrain2Result SwarmNoteNotNoMeterDrain2(const SwarmNotNoMeterDrain2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMETERDRAIN2_H
