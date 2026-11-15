// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTTFT_H
#define BTX_MODELNET_SWARM_NOTTTFT_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_publish asks this note to publish a
 * time-to-first-token measurement.
 *
 * No time-to-first-token has been measured, so this note does not publish one.
 * published stays false on every path.
 */
struct SwarmNotTtft {
    std::string node_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a time-to-first-token request. published stays false on
 * every path: no time-to-first-token has been measured, so this note does not
 * publish one.
 */
struct SwarmNotTtftResult {
    std::string code;
    bool published{false};
};

/**
 * Note a time-to-first-token request without publishing one.
 * Order, first match wins: an empty node_id is TTFT.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false on every path.
 */
SwarmNotTtftResult SwarmNoteNotTtft(const SwarmNotTtft& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTTFT_H
