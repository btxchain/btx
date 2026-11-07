// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTAIL_H
#define BTX_MODELNET_SWARM_NOTNOTAIL_H

#include <string>

namespace modelnet {

/**
 * A local note about one output. want_complete asks this note to treat the
 * output as complete.
 *
 * A truncated output is not a complete result, so this note does not complete
 * one and does not move bytes. complete and bytes_moved stay false on every
 * path.
 */
struct SwarmNotNoTail {
    std::string output_id;
    bool truncated{false};
    bool want_complete{false};
};

/**
 * Outcome of noting an output. complete and bytes_moved stay false on every
 * path: a truncated output is not a complete result.
 */
struct SwarmNotNoTailResult {
    std::string code;
    bool complete{false};
    bool bytes_moved{false};
};

/**
 * Note an output without treating a truncated output as complete. Order,
 * first match wins: an empty output_id is OUTPUT. truncated is NOT_COMPLETE
 * even when want_complete is false. want_complete is NOT_COMPLETE. Otherwise
 * the note is NOTED and err is cleared. complete and bytes_moved stay false
 * on every path. A truncated output is not a complete result.
 */
SwarmNotNoTailResult SwarmNoteNotNoTail(const SwarmNotNoTail& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTAIL_H
