// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSANDBOXCAP2_H
#define BTX_MODELNET_SWARM_NOTNOSANDBOXCAP2_H

#include <string>

namespace modelnet {

/**
 * A local note that a sandbox might be raised.
 * want_raise asks this note to raise one.
 *
 * A sandbox raise stays capped. raised stays false on every path.
 */
struct SwarmNotNoSandboxCap2 {
    std::string sandbox_id;
    bool want_raise{false};
};

/**
 * Outcome of noting that a sandbox raise stays capped.
 * raised stays false on every path.
 */
struct SwarmNotNoSandboxCap2Result {
    std::string code;
    bool raised{false};
};

/**
 * Note that a sandbox raise stays capped.
 * Order, first match wins: an empty sandbox_id is SANDBOX. want_raise is
 * CAPPED. Otherwise the note is NOTED and err is cleared. raised stays
 * false on every path.
 */
SwarmNotNoSandboxCap2Result SwarmNoteNotNoSandboxCap2(const SwarmNotNoSandboxCap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSANDBOXCAP2_H
