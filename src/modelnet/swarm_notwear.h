// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTWEAR_H
#define BTX_MODELNET_SWARM_NOTWEAR_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Note that hardware wear was not measured.
 *  published stays false and wear stays 0. This note does not read hardware wear.
 */
struct SwarmNotWear {
    std::string device_id;
    bool want_publish{false};
};

struct SwarmNotWearResult {
    std::string code;
    bool published{false};
    int64_t wear{0};
};

/** Note an unmeasured wear record. Publication does not happen.
 *  Order, first match wins:
 *  1. An empty device_id is DEVICE. published stays false, wear stays 0, and err is DEVICE.
 *  2. want_publish is UNMEASURED. published stays false, wear stays 0, and err is UNMEASURED.
 *  3. Otherwise the note is NOTED. published stays false, wear stays 0, and err is cleared.
 *  This note does not read hardware wear.
 */
SwarmNotWearResult SwarmNoteNotWear(const SwarmNotWear& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTWEAR_H
