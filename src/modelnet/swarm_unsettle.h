// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_UNSETTLE_H
#define BTX_MODELNET_SWARM_UNSETTLE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One earning note. atoms is the recorded amount. Noting an earning does
 * not settle and does not broadcast.
 */
struct SwarmEarning {
    std::string earning_id;
    int64_t atoms{0};
    bool crash_before_settlement{false};
    bool want_broadcast{false};
};

/**
 * Note answer. settled and broadcast stay false.
 */
struct SwarmEarningResult {
    bool recorded{false};
    bool settled{false};
    bool broadcast{false};
    int64_t atoms{0};
    std::string code;
};

/**
 * Notes one earning. settled and broadcast stay false.
 *
 * Order: an empty earning_id or atoms <= 0 is UNSETTLED. want_broadcast is
 * BROADCAST_FORBIDDEN, even when crash_before_settlement is true.
 * crash_before_settlement is HELD, recorded is true, atoms are copied, and
 * err is cleared. Otherwise the result is RECORDED, recorded is true, atoms
 * are copied, and err is cleared.
 */
SwarmEarningResult SwarmNoteEarning(const SwarmEarning& earning, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_UNSETTLE_H
