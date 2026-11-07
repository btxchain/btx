// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSLOTS_H
#define BTX_MODELNET_SWARM_NOTNOSLOTS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about device slots. want_open asks this note to open a slot.
 *
 * The default without a device file opens one slot and this note opens none.
 * opened stays false and applied stays 0 on every path.
 */
struct SwarmNotNoSlots {
    std::string node_id;
    int64_t slots{0};
    bool want_open{false};
};

/**
 * Outcome of noting a slot request. opened stays false and applied stays 0
 * on every path. The default without a device file opens one slot and this
 * note opens none.
 */
struct SwarmNotNoSlotsResult {
    std::string code;
    bool opened{false};
    int64_t applied{0};
};

/**
 * Note a slot request without opening any.
 * Order, first match wins: an empty node_id is NODE. slots not exactly 1
 * is CAPPED even when want_open is false. want_open is CAPPED. Otherwise
 * the note is NOTED and err is clear. opened stays false and applied stays
 * 0 on every path. The default without a device file opens one slot and
 * this note opens none.
 */
SwarmNotNoSlotsResult SwarmNoteNotNoSlots(const SwarmNotNoSlots& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSLOTS_H
