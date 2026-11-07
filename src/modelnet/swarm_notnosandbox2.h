// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSANDBOX2_H
#define BTX_MODELNET_SWARM_NOTNOSANDBOX2_H

#include <string>

namespace modelnet {

/**
 * A local note that a sandbox might be raised.
 * want_raise asks this note to raise one.
 *
 * A sandbox raise stays capped. raised stays false and cap stays 0 on
 * every path.
 */
struct SwarmNotNoSandbox2 {
    std::string sandbox_id;
    bool want_raise{false};
};

/**
 * Outcome of noting that a sandbox raise stays capped.
 * raised stays false and cap stays 0 on every path.
 */
struct SwarmNotNoSandbox2Result {
    std::string code;
    bool raised{false};
    int cap{0};
};

/**
 * Note that a sandbox raise stays capped.
 * Order, first match wins: an empty sandbox_id is SANDBOX. want_raise is
 * CAPPED. Otherwise the note is NOTED and err is cleared. raised stays
 * false and cap stays 0 on every path.
 */
SwarmNotNoSandbox2Result SwarmNoteNotNoSandbox2(const SwarmNotNoSandbox2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSANDBOX2_H
