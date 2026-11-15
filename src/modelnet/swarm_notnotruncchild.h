// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRUNCCHILD_H
#define BTX_MODELNET_SWARM_NOTNOTRUNCCHILD_H

#include <string>

namespace modelnet {

/**
 * A local note about one child. want_stream asks this note to stream it.
 * truncated marks that the child is truncated.
 *
 * A truncated child streams nothing and does not activate, so streamed
 * stays false and activated stays false on every path.
 */
struct SwarmNotNoTruncChild {
    std::string child_id;
    bool truncated{false};
    bool want_stream{false};
};

/**
 * Outcome of noting a child. streamed and activated stay false on
 * every path: a truncated child streams nothing and does not activate.
 */
struct SwarmNotNoTruncChildResult {
    std::string code;
    bool streamed{false};
    bool activated{false};
};

/**
 * Note a child without streaming it. Order, first match wins: an empty
 * child_id is CHILD. truncated is NOT_STREAMED even when want_stream is
 * false. want_stream is HELD. Otherwise the note is NOTED and err is
 * cleared. streamed and activated stay false on every path. A truncated
 * child streams nothing and does not activate.
 */
SwarmNotNoTruncChildResult SwarmNoteNotNoTruncChild(const SwarmNotNoTruncChild& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRUNCCHILD_H
