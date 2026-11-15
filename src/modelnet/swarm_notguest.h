// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTGUEST_H
#define BTX_MODELNET_SWARM_NOTGUEST_H

#include <string>

namespace modelnet {

/**
 * A local note about a Windows guest. want_pass asks this note to treat
 * the guest as a pass.
 *
 * A Windows guest with no login path that leaves the signer alone is not a
 * pass, so passed stays false on every path.
 */
struct SwarmNotGuest {
    std::string guest_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a Windows guest. passed stays false on every path.
 */
struct SwarmNotGuestResult {
    std::string code;
    bool passed{false};
};

/**
 * Note that a Windows guest is not a pass.
 * Order, first match wins: an empty guest_id is GUEST. want_pass is
 * UNQUALIFIED. Otherwise the note is NOTED and err is clear.
 * passed stays false on every path. A Windows guest with no login path
 * that leaves the signer alone is not a pass.
 */
SwarmNotGuestResult SwarmNoteNotGuest(const SwarmNotGuest& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTGUEST_H
