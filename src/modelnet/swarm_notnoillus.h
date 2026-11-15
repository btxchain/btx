// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOILLUS_H
#define BTX_MODELNET_SWARM_NOTNOILLUS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one revenue split. want_pay asks this note to pay.
 *
 * A revenue illustration of 700000, 200000, and 100000 ppm on a gross of
 * 10000 records 7000, 2000, and 1000 and pays nothing. paid stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoIllus {
    std::string split_id;
    bool want_pay{false};
};

/**
 * Outcome of noting a revenue split. paid stays false and atoms stays 0
 * on every path. A revenue illustration of 700000, 200000, and 100000 ppm
 * on a gross of 10000 records 7000, 2000, and 1000 and pays nothing.
 */
struct SwarmNotNoIllusResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a revenue split without paying.
 * Order, first match wins: an empty split_id is SPLIT. want_pay is
 * NOT_PAID. Otherwise the note is NOTED and err is cleared.
 * paid stays false and atoms stays 0 on every path. A revenue
 * illustration of 700000, 200000, and 100000 ppm on a gross of 10000
 * records 7000, 2000, and 1000 and pays nothing.
 */
SwarmNotNoIllusResult SwarmNoteNotNoIllus(const SwarmNotNoIllus& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOILLUS_H
