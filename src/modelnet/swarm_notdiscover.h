// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDISCOVER_H
#define BTX_MODELNET_SWARM_NOTDISCOVER_H

#include <string>

namespace modelnet {

/**
 * A local note about one runtime. want_discover asks this note to scan
 * for that runtime and launch one.
 *
 * This note does not scan for a runtime or launch one. discovered and
 * launched stay false on every path.
 */
struct SwarmNotDiscover {
    std::string runtime_id;
    bool want_discover{false};
};

/**
 * Outcome of noting a discover request. discovered and launched stay
 * false on every path: this note does not scan for a runtime or launch one.
 */
struct SwarmNotDiscoverResult {
    std::string code;
    bool discovered{false};
    bool launched{false};
};

/**
 * Note a discover request without scanning for a runtime or launching one.
 * Order, first match wins: an empty runtime_id is RUNTIME. want_discover is
 * NOT_FOUND. Otherwise the note is NOTED and err is clear.
 * discovered and launched stay false on every path. This note does not scan
 * for a runtime or launch one.
 */
SwarmNotDiscoverResult SwarmNoteNotDiscover(const SwarmNotDiscover& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDISCOVER_H
