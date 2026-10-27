// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SLOT1_H
#define BTX_MODELNET_SWARM_SLOT1_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A default note when device.json is absent. node_id names the note.
 * device_json_present marks a present device file. requested_slots is
 * the slot count the caller asked to record. want_launch asks this note
 * to launch a slot.
 *
 * When device.json is absent the default slot count is 1. This note
 * does not read a file and does not launch a slot. launched stays false
 * on every path. Nothing is started. No hostnames or IPs are used.
 */
struct SwarmDefaultSlots {
    std::string node_id;
    bool device_json_present{false};
    int64_t requested_slots{0};
    bool want_launch{false};
};

/**
 * Outcome of noting the default slot count when device.json is absent.
 * launched stays false: this note does not launch a slot. Nothing is
 * started.
 */
struct SwarmDefaultSlotsResult {
    int64_t slots{0};
    bool launched{false};
    std::string code;
};

/**
 * Note the default slot count when device.json is absent. This note
 * does not read a file and does not launch a slot.
 * Order, first match wins: an empty node_id or requested_slots below 0
 * is SLOTS. device_json_present is PRESENT: this note does not interpret
 * a present device file. requested_slots other than 1 is NOT_DEFAULT.
 * This wins even when want_launch is true. want_launch is HELD, slots
 * is 1, and err is cleared. Otherwise the note is NOTED, slots is 1,
 * and err is cleared. When device.json is absent the default slot count
 * is 1.
 * launched stays false on every path. Nothing is started. No hostnames
 * or IPs are used.
 */
SwarmDefaultSlotsResult SwarmNoteDefaultSlots(const SwarmDefaultSlots& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SLOT1_H
