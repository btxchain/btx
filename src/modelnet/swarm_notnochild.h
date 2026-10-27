// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHILD_H
#define BTX_MODELNET_SWARM_NOTNOCHILD_H

#include <string>

namespace modelnet {

/**
 * A local note about one manifest. want_stream asks this note to stream.
 * child_matches marks that the child matches.
 *
 * A missing, truncated, reordered, wrong-digest, or wrong-length child
 * streams nothing and activates nothing, so streamed stays false and
 * activated stays false on every path. A manifest root is not proof of
 * its children.
 */
struct SwarmNotNoChild {
    std::string manifest_id;
    bool child_matches{false};
    bool want_stream{false};
};

/**
 * Outcome of noting a manifest. streamed stays false and activated stays
 * false on every path. A missing, truncated, reordered, wrong-digest, or
 * wrong-length child streams nothing and activates nothing. A manifest
 * root is not proof of its children.
 */
struct SwarmNotNoChildResult {
    std::string code;
    bool streamed{false};
    bool activated{false};
};

/**
 * Note a manifest without streaming or activating a child.
 * Order, first match wins: an empty manifest_id is MANIFEST.
 * child_matches false is INCOMPLETE even when want_stream is false.
 * want_stream is HELD. Otherwise the note is NOTED and err is cleared.
 * streamed stays false and activated stays false on every path. A
 * missing, truncated, reordered, wrong-digest, or wrong-length child
 * streams nothing and activates nothing. A manifest root is not proof
 * of its children.
 */
SwarmNotNoChildResult SwarmNoteNotNoChild(const SwarmNotNoChild& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHILD_H
