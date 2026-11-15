// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOST_H
#define BTX_MODELNET_SWARM_NOTNOCOST_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. unmeasured marks electricity or wear as
 * unmeasured. want_charge asks this note to charge.
 *
 * An unmeasured electricity or wear cost charges nothing. charged stays
 * false and atoms stays 0 on every path.
 */
struct SwarmNotNoCost {
    std::string run_id;
    bool unmeasured{false};
    bool want_charge{false};
};

/**
 * Outcome of noting a cost. charged stays false and atoms stays 0 on
 * every path. An unmeasured electricity or wear cost charges nothing.
 */
struct SwarmNotNoCostResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a cost without charging it.
 * Order, first match wins: an empty run_id is RUN. unmeasured true is
 * UNMEASURED even when want_charge is false. want_charge is HELD.
 * Otherwise the note is NOTED and err is cleared. charged stays false
 * and atoms stays 0 on every path. An unmeasured electricity or wear
 * cost charges nothing.
 */
SwarmNotNoCostResult SwarmNoteNotNoCost(const SwarmNotNoCost& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOST_H
