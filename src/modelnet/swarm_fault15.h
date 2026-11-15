// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT15_H
#define BTX_MODELNET_SWARM_FAULT15_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Live fault 15: multiple channels exit during a reorganization.
 * measured, broadcast, and committed stay false.
 * 8000 bytes is not a measurement; assumed_bytes stays 0.
 */
struct SwarmFault15 {
    std::string batch_id;
    int channel_count{0};
    bool want_measure{false};
    bool want_broadcast{false};
};

struct SwarmFault15Result {
    std::string code;
    bool measured{false};
    bool broadcast{false};
    bool committed{false};
    int64_t assumed_bytes{0};
};

/**
 * Empty batch_id, or channel_count below 2, is BATCH and sets err.
 * want_measure is MEASURE_REFUSED and sets err, even when want_broadcast is set.
 * want_broadcast is HELD and clears err. Otherwise NOTED and clears err.
 * This function does not measure, broadcast, or commit.
 */
SwarmFault15Result SwarmRecoverFault15(const SwarmFault15& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT15_H
