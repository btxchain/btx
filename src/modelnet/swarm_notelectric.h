// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTELECTRIC_H
#define BTX_MODELNET_SWARM_NOTELECTRIC_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Note that watt-hours were not measured.
 *  published stays false and watt_hours stays 0. This note does not read a meter.
 */
struct SwarmNotElectric {
    std::string meter_id;
    bool want_publish{false};
};

struct SwarmNotElectricResult {
    std::string code;
    bool published{false};
    int64_t watt_hours{0};
};

/** Note an unmeasured watt-hours record. Publication does not happen.
 *  Order, first match wins:
 *  1. An empty meter_id is METER. published stays false, watt_hours stays 0, and err is METER.
 *  2. want_publish is UNMEASURED. published stays false, watt_hours stays 0, and err is UNMEASURED.
 *  3. Otherwise the note is NOTED. published stays false, watt_hours stays 0, and err is cleared.
 *  Nothing here reads a meter.
 */
SwarmNotElectricResult SwarmNoteNotElectric(const SwarmNotElectric& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTELECTRIC_H
