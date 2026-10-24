// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREORDER_H
#define BTX_MODELNET_SWARM_NOTNOREORDER_H

#include <string>

namespace modelnet {

/**
 * A local note about one child. reordered marks that the child was
 * reordered. want_stream asks this note to stream.
 *
 * A reordered child streams nothing and does not activate, so streamed
 * stays false and activated stays false on every path.
 */
struct SwarmNotNoReorder {
    std::string child_id;
    bool reordered{false};
    bool want_stream{false};
};

/**
 * Outcome of noting a child. streamed stays false and activated stays
 * false on every path. A reordered child streams nothing and does not
 * activate.
 */
struct SwarmNotNoReorderResult {
    std::string code;
    bool streamed{false};
    bool activated{false};
};

/**
 * Note a child without streaming or activating it.
 * Order, first match wins: an empty child_id is CHILD. reordered is
 * NOT_STREAMED even when want_stream is false. want_stream is HELD.
 * Otherwise the note is NOTED and err is cleared. streamed stays false
 * and activated stays false on every path. A reordered child streams
 * nothing and does not activate.
 */
SwarmNotNoReorderResult SwarmNoteNotNoReorder(const SwarmNotNoReorder& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREORDER_H
