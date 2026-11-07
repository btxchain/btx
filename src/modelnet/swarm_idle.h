// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_IDLE_H
#define BTX_MODELNET_SWARM_IDLE_H

#include <string>

namespace modelnet {

/**
 * A default note when device.json is absent. node_id names the note.
 * device_json_present marks a present device file. want_train asks to
 * train. want_spend asks this note to arm a spend. want_private asks
 * for a private role.
 *
 * This note does not read a file. trainer stays false, spend_armed
 * stays false, and spend stays "0" on every path. Nothing is signed
 * and nothing is broadcast. No hostnames or IPs are used.
 */
struct SwarmIdleDefault {
    std::string node_id;
    bool device_json_present{false};
    bool want_train{false};
    bool want_spend{false};
    bool want_private{false};
};

/**
 * Outcome of noting the default when device.json is absent. trainer
 * stays false, spend_armed stays false, and spend stays "0": this note
 * does not train and spending stays off. An absent device file yields
 * a seeder and an evaluator only on the noted path. Nothing is signed
 * and nothing is broadcast.
 */
struct SwarmIdleDefaultResult {
    bool trainer{false};
    bool seeder{false};
    bool evaluator{false};
    bool spend_armed{false};
    std::string spend;
    std::string code;
};

/**
 * Note the default when device.json is absent. This note does not read
 * a file. Order, first match wins: an empty node_id is IDLE.
 * device_json_present is PRESENT: this note does not interpret a
 * present device file. want_train is NOT_TRAINER, even when want_spend
 * or want_private is true. want_spend is SPEND_REFUSED. want_private
 * is PRIVATE_REFUSED. Otherwise the note is NOTED, seeder and evaluator
 * are true, and err is cleared. An absent device file yields a seeder
 * and an evaluator, not a trainer, and spending stays off.
 * trainer stays false, spend_armed stays false, and spend stays "0"
 * on every path. Nothing is signed and nothing is broadcast.
 */
SwarmIdleDefaultResult SwarmNoteIdleDefault(const SwarmIdleDefault& idle, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_IDLE_H
