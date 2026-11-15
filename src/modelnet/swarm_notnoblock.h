// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBLOCK_H
#define BTX_MODELNET_SWARM_NOTNOBLOCK_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish.
 *
 * A safety failure or a broad regression is not published.
 * published and admitted stay false on every path.
 */
struct SwarmNotNoBlock {
    std::string run_id;
    bool safety_fail{false};
    bool broad_regression{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a run. published and admitted stay false on every
 * path: a safety failure or a broad regression is not published.
 */
struct SwarmNotNoBlockResult {
    std::string code;
    bool published{false};
    bool admitted{false};
};

/**
 * Note a run without publishing it or admitting it.
 * Order, first match wins: an empty run_id is RUN. safety_fail or
 * broad_regression is BLOCK even when want_publish is false.
 * want_publish is BLOCK. Otherwise the note is NOTED and err is
 * cleared. published and admitted stay false on every path. A safety
 * failure or a broad regression is not published.
 */
SwarmNotNoBlockResult SwarmNoteNotNoBlock(const SwarmNotNoBlock& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBLOCK_H
