// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSLOTS2_H
#define BTX_MODELNET_SWARM_NOTNOSLOTS2_H

#include <string>

namespace modelnet {

/**
 * A local note about slots for one node. want_raise asks this note to
 * raise one.
 *
 * Default slots stay 1. This note raises nothing. raised stays false and
 * slots stays 0 on every path.
 */
struct SwarmNotNoSlots2 {
    std::string node_id;
    bool want_raise{false};
};

/**
 * Outcome of noting a slot request. raised stays false and slots stays 0
 * on every path. Default slots stay 1. This note raises nothing.
 */
struct SwarmNotNoSlots2Result {
    std::string code;
    bool raised{false};
    int slots{0};
};

/**
 * Note a slot request without raising any.
 * Order, first match wins: an empty node_id is NODE. want_raise is HELD.
 * Otherwise the note is NOTED and err is cleared. raised stays false and
 * slots stays 0 on every path. Default slots stay 1. This note raises
 * nothing.
 */
SwarmNotNoSlots2Result SwarmNoteNotNoSlots2(const SwarmNotNoSlots2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSLOTS2_H
