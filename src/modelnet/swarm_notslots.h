// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSLOTS_H
#define BTX_MODELNET_SWARM_NOTSLOTS_H

#include <string>

namespace modelnet {

/**
 * A local note about the slot count for one node.
 * The default without device.json is one slot.
 *
 * This note launches nothing, so raised stays false and applied_slots stays
 * 0 on every path.
 */
struct SwarmNotSlots {
    std::string node_id;
    int slot_count{0};
    bool want_raise{false};
};

/**
 * Outcome of noting a slot count. raised stays false and applied_slots stays
 * 0 on every path: this note launches nothing.
 */
struct SwarmNotSlotsResult {
    std::string code;
    bool raised{false};
    int applied_slots{0};
};

/**
 * Note a slot count without launching anything.
 * Order, first match wins: an empty node_id is NODE. If slot_count is not
 * exactly 1, the note is CAPPED even when want_raise is false. want_raise
 * is CAPPED. Otherwise the note is NOTED and err is clear. raised stays
 * false and applied_slots stays 0 on every path. The default without
 * device.json is one slot. This note launches nothing.
 */
SwarmNotSlotsResult SwarmNoteNotSlots(const SwarmNotSlots& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSLOTS_H
