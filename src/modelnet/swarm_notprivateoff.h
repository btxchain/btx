// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPRIVATEOFF_H
#define BTX_MODELNET_SWARM_NOTPRIVATEOFF_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_private asks this note to store a
 * private prompt.
 *
 * Private prompts stay off by default. This note stores no prompt, so
 * accepted and stored stay false on every path.
 */
struct SwarmNotPrivateOff {
    std::string node_id;
    bool want_private{false};
};

/**
 * Outcome of noting a private-prompt request. accepted and stored stay
 * false on every path. This note stores no prompt.
 */
struct SwarmNotPrivateOffResult {
    std::string code;
    bool accepted{false};
    bool stored{false};
};

/**
 * Note that private prompts stay off and this note stores no prompt.
 * Order, first match wins: an empty node_id is NODE. want_private is
 * PRIVATE_OFF. Otherwise the note is NOTED and err is cleared.
 * accepted and stored stay false on every path. Private prompts stay
 * off by default. This note stores no prompt.
 */
SwarmNotPrivateOffResult SwarmNoteNotPrivateOff(const SwarmNotPrivateOff& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPRIVATEOFF_H
