// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTOMIT_H
#define BTX_MODELNET_SWARM_NOTOMIT_H

#include <string>

namespace modelnet {

/**
 * A local note about one target. default_build marks the default build.
 * want_omit asks this note to omit the core swarm lifecycle.
 *
 * The default build must not silently omit the core swarm lifecycle.
 * omitted stays false on every path.
 */
struct SwarmNotOmit {
    std::string target_id;
    bool default_build{false};
    bool want_omit{false};
};

/**
 * Outcome of noting an omit request. omitted stays false on every path.
 * The default build must not silently omit the core swarm lifecycle.
 */
struct SwarmNotOmitResult {
    std::string code;
    bool omitted{false};
};

/**
 * Note an omit request without omitting the core swarm lifecycle.
 * Order, first match wins: an empty target_id is TARGET.
 * default_build and want_omit is PRESENT.
 * Otherwise the note is NOTED and err is clear.
 * omitted stays false on every path.
 * The default build must not silently omit the core swarm lifecycle.
 */
SwarmNotOmitResult SwarmNoteNotOmit(const SwarmNotOmit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTOMIT_H
