// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVERIFIED_H
#define BTX_MODELNET_SWARM_NOTNOVERIFIED_H

#include <string>

namespace modelnet {

/**
 * A local note about one book. unverified marks a book that is not
 * verified. want_activate asks this note to activate.
 *
 * Activation happens only from a verified book, so activated stays false
 * and bytes_moved stays false on every path.
 */
struct SwarmNotNoVerified {
    std::string book_id;
    bool unverified{false};
    bool want_activate{false};
};

/**
 * Outcome of noting a book. activated stays false and bytes_moved stays
 * false on every path. Activation happens only from a verified book.
 */
struct SwarmNotNoVerifiedResult {
    std::string code;
    bool activated{false};
    bool bytes_moved{false};
};

/**
 * Note a book without activating it.
 * Order, first match wins: an empty book_id is BOOK. unverified true is
 * NOT_ACTIVE even when want_activate is false. want_activate is HELD.
 * Otherwise the note is NOTED and err is cleared. activated stays false
 * and bytes_moved stays false on every path. Activation happens only
 * from a verified book.
 */
SwarmNotNoVerifiedResult SwarmNoteNotNoVerified(const SwarmNotNoVerified& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVERIFIED_H
