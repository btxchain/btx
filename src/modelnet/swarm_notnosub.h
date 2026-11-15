// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSUB_H
#define BTX_MODELNET_SWARM_NOTNOSUB_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one subscription. want_charge asks this note to
 * charge that subscription.
 *
 * A subscription note charges nothing. charged stays false and atoms
 * stays 0 on every path.
 */
struct SwarmNotNoSub {
    std::string sub_id;
    bool want_charge{false};
};

/**
 * Outcome of noting a subscription. charged stays false and atoms stays
 * 0 on every path. A subscription note charges nothing.
 */
struct SwarmNotNoSubResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a subscription without charging it or moving atoms.
 * Order, first match wins: an empty sub_id is SUB. want_charge is
 * NOT_CHARGED. Otherwise the note is NOTED and err is clear.
 * charged stays false and atoms stays 0 on every path.
 * A subscription note charges nothing.
 */
SwarmNotNoSubResult SwarmNoteNotNoSub(const SwarmNotNoSub& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSUB_H
