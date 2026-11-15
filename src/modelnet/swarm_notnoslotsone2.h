// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSLOTSONE2_H
#define BTX_MODELNET_SWARM_NOTNOSLOTSONE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about slots for one node. no_device means there is no
 * device file. want_raise asks this note to raise the slot count.
 *
 * Without a device file the slot count stays 1. raised stays false and
 * slots stays 1 on every path.
 */
struct SwarmNotNoSlotsOne2 {
    std::string node_id;
    bool no_device{false};
    bool want_raise{false};
};

/**
 * Outcome of noting a slot request. raised stays false and slots stays 1
 * on every path. Without a device file the slot count stays 1.
 */
struct SwarmNotNoSlotsOne2Result {
    std::string code;
    bool raised{false};
    int64_t slots{1};
};

/**
 * Note a slot request without raising any.
 * Order, first match wins: an empty node_id is NODE. no_device is
 * SLOTS_ONE even when want_raise is false. want_raise is HELD. Otherwise
 * the note is NOTED and err is cleared. raised stays false and slots stays
 * 1 on every path. Without a device file the slot count stays 1.
 */
SwarmNotNoSlotsOne2Result SwarmNoteNotNoSlotsOne2(const SwarmNotNoSlotsOne2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSLOTSONE2_H
