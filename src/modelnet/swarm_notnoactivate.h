// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOACTIVATE_H
#define BTX_MODELNET_SWARM_NOTNOACTIVATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one book. want_activate asks this note to activate.
 * verified marks a verified book.
 *
 * Activation happens only from a verified book and moves no bytes, so
 * activated stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoActivate {
    std::string book_id;
    bool verified{false};
    bool want_activate{false};
};

/**
 * Outcome of noting a book. activated stays false and bytes_moved stays
 * false on every path. Activation happens only from a verified book and
 * moves no bytes.
 */
struct SwarmNotNoActivateResult {
    std::string code;
    bool activated{false};
    bool bytes_moved{false};
};

/**
 * Note a book without activating it.
 * Order, first match wins: an empty book_id is BOOK. verified false is
 * NOT_VERIFIED even when want_activate is false. want_activate is HELD.
 * Otherwise the note is NOTED and err is cleared. activated stays false
 * and bytes_moved stays false on every path. Activation happens only
 * from a verified book and moves no bytes.
 */
SwarmNotNoActivateResult SwarmNoteNotNoActivate(const SwarmNotNoActivate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOACTIVATE_H
