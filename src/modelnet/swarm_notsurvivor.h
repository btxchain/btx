// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSURVIVOR_H
#define BTX_MODELNET_SWARM_NOTSURVIVOR_H

#include <string>

namespace modelnet {

/**
 * A local note about one surviving node. want_continue asks this note to
 * continue after the original coordinator permanently disappears.
 *
 * A survivor continuing after the original coordinator permanently disappears
 * has not been shown. continued stays false on every path.
 */
struct SwarmNotSurvivor {
    std::string node_id;
    bool want_continue{false};
};

/**
 * Outcome of noting a survivor request. continued stays false on every path:
 * a survivor continuing after the original coordinator permanently disappears
 * has not been shown.
 */
struct SwarmNotSurvivorResult {
    std::string code;
    bool continued{false};
};

/**
 * Note a survivor request without continuing the surviving node.
 * Order, first match wins: an empty node_id is NODE. want_continue is
 * NOT_SHOWN. Otherwise the note is NOTED and err is clear.
 * continued stays false on every path. A survivor continuing after the
 * original coordinator permanently disappears has not been shown.
 */
SwarmNotSurvivorResult SwarmNoteNotSurvivor(const SwarmNotSurvivor& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSURVIVOR_H
