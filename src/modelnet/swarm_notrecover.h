// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTRECOVER_H
#define BTX_MODELNET_SWARM_NOTRECOVER_H

#include <string>

namespace modelnet {

/**
 * A local note about one surviving node. want_continue asks this note to
 * continue after the coordinator process was terminated.
 *
 * A surviving node has not continued after the coordinator process was
 * terminated. continued stays false on every path.
 */
struct SwarmNotRecover {
    std::string node_id;
    bool want_continue{false};
};

/**
 * Outcome of noting a recover request. continued stays false on every path:
 * a surviving node has not continued after the coordinator process was
 * terminated.
 */
struct SwarmNotRecoverResult {
    std::string code;
    bool continued{false};
};

/**
 * Note a recover request without continuing the surviving node.
 * Order, first match wins: an empty node_id is NODE. want_continue is
 * NOT_CONTINUED. Otherwise the note is NOTED and err is clear.
 * continued stays false on every path. A surviving node has not continued
 * after the coordinator process was terminated.
 */
SwarmNotRecoverResult SwarmNoteNotRecover(const SwarmNotRecover& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTRECOVER_H
