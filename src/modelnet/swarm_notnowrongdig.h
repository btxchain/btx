// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWRONGDIG_H
#define BTX_MODELNET_SWARM_NOTNOWRONGDIG_H

#include <string>

namespace modelnet {

/**
 * A local note about one child. wrong_digest marks that the child digest
 * does not match. want_stream asks this note to stream.
 *
 * A wrong-digest child streams nothing and does not activate, so streamed
 * stays false and activated stays false on every path.
 */
struct SwarmNotNoWrongDig {
    std::string child_id;
    bool wrong_digest{false};
    bool want_stream{false};
};

/**
 * Outcome of noting a child. streamed stays false and activated stays
 * false on every path. A wrong-digest child streams nothing and does not
 * activate.
 */
struct SwarmNotNoWrongDigResult {
    std::string code;
    bool streamed{false};
    bool activated{false};
};

/**
 * Note a child without streaming or activating it.
 * Order, first match wins: an empty child_id is CHILD. wrong_digest is
 * NOT_STREAMED even when want_stream is false. want_stream is HELD.
 * Otherwise the note is NOTED and err is cleared. streamed stays false
 * and activated stays false on every path. A wrong-digest child streams
 * nothing and does not activate.
 */
SwarmNotNoWrongDigResult SwarmNoteNotNoWrongDig(const SwarmNotNoWrongDig& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWRONGDIG_H
