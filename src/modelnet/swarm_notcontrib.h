// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCONTRIB_H
#define BTX_MODELNET_SWARM_NOTCONTRIB_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one worker. want_publish asks this note to publish
 * a contribution.
 *
 * Contributions stay unpublished and unaccepted. published and accepted
 * stay false on every path. count stays 0 on every path.
 */
struct SwarmNotContrib {
    std::string worker_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a contribution request. published and accepted stay
 * false on every path. count stays 0: nothing is published or accepted.
 */
struct SwarmNotContribResult {
    std::string code;
    bool published{false};
    bool accepted{false};
    int64_t count{0};
};

/**
 * Note a contribution request without publishing or accepting it.
 * Order, first match wins: an empty worker_id is WORKER. want_publish
 * is UNVERIFIED. Otherwise the note is NOTED and err is clear.
 * published and accepted stay false on every path. count stays 0 on
 * every path.
 */
SwarmNotContribResult SwarmNoteNotContrib(const SwarmNotContrib& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCONTRIB_H
