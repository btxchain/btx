// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_slot1.h>

#include <cstdint>

namespace modelnet {

SwarmDefaultSlotsResult SwarmNoteDefaultSlots(const SwarmDefaultSlots& note, std::string& err)
{
    SwarmDefaultSlotsResult result;
    result.slots = 0;
    result.launched = false;
    if (note.node_id.empty() || note.requested_slots < 0) {
        result.code = "SLOTS";
        result.slots = 0;
        result.launched = false;
        err = "SLOTS";
        return result;
    }
    // This note does not interpret a present device file.
    if (note.device_json_present) {
        result.code = "PRESENT";
        result.slots = 0;
        result.launched = false;
        err = "PRESENT";
        return result;
    }
    // requested_slots other than 1 is not the default.
    // This wins even when want_launch is true. Nothing is started.
    if (note.requested_slots != 1) {
        result.code = "NOT_DEFAULT";
        result.slots = 0;
        result.launched = false;
        err = "NOT_DEFAULT";
        return result;
    }
    // want_launch holds the default slot. This note does not launch a slot.
    if (note.want_launch) {
        result.code = "HELD";
        result.slots = 1;
        result.launched = false;
        err.clear();
        return result;
    }
    // When device.json is absent the default slot count is 1.
    // Nothing is started.
    result.code = "NOTED";
    result.slots = 1;
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
