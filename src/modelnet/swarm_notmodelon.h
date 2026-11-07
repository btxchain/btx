// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMODELON_H
#define BTX_MODELNET_SWARM_NOTMODELON_H

#include <string>

namespace modelnet {

/**
 * A local note about ModelNet on one node. modelnet_on records that
 * ModelNet defaults on. want_disable asks this note to turn ModelNet off.
 *
 * ModelNet defaults on. This note does not change a flag or launch a
 * process. disabled stays false on every path.
 */
struct SwarmNotModelOn {
    std::string node_id;
    bool modelnet_on{true};
    bool want_disable{false};
};

/**
 * Outcome of noting ModelNet. disabled stays false on every path.
 * ModelNet defaults on. This note does not change a flag or launch a
 * process.
 */
struct SwarmNotModelOnResult {
    std::string code;
    bool disabled{false};
};

/**
 * Note ModelNet without changing a flag or launching a process.
 * Order, first match wins: an empty node_id is NODE. If modelnet_on is
 * false the code is DEFAULT_ON even when want_disable is false.
 * want_disable is DEFAULT_ON. Otherwise the note is NOTED and err is
 * cleared. disabled stays false on every path. ModelNet defaults on.
 */
SwarmNotModelOnResult SwarmNoteNotModelOn(const SwarmNotModelOn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMODELON_H
