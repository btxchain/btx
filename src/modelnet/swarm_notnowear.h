// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWEAR_H
#define BTX_MODELNET_SWARM_NOTNOWEAR_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about hardware wear. device_id names the device.
 * want_claim asks this note to claim wear hours.
 *
 * This note publishes no wear hours. claimed stays false and hours
 * stays 0 on every path.
 */
struct SwarmNotNoWear {
    std::string device_id;
    bool want_claim{false};
};

/**
 * Outcome of noting wear. claimed stays false and hours stays 0 on
 * every path: this note publishes no wear hours.
 */
struct SwarmNotNoWearResult {
    std::string code;
    bool claimed{false};
    int64_t hours{0};
};

/**
 * Note wear without publishing hours.
 * Order, first match wins: an empty device_id is DEVICE.
 * want_claim is UNMEASURED.
 * Otherwise the note is NOTED and err is cleared.
 * claimed stays false and hours stays 0 on every path. This note
 * publishes no wear hours.
 */
SwarmNotNoWearResult SwarmNoteNotNoWear(const SwarmNotNoWear& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWEAR_H
