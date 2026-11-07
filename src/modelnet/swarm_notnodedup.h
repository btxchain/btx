// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODEDUP_H
#define BTX_MODELNET_SWARM_NOTNODEDUP_H

#include <string>

namespace modelnet {

/**
 * A local note about one piece. other_realm marks the piece as
 * belonging to another realm. want_dedup asks this note to dedup it.
 *
 * Dedup across realms moves no bytes.
 * deduped and bytes_moved stay false on every path.
 */
struct SwarmNotNoDedup {
    std::string piece_id;
    bool other_realm{false};
    bool want_dedup{false};
};

/**
 * Outcome of noting a piece. deduped and bytes_moved stay false on every
 * path. Dedup across realms moves no bytes.
 */
struct SwarmNotNoDedupResult {
    std::string code;
    bool deduped{false};
    bool bytes_moved{false};
};

/**
 * Note a piece without deduping or moving bytes. Order, first match
 * wins: an empty piece_id is PIECE. other_realm is DEDUP_PRIVATE even when
 * want_dedup is false. want_dedup is HELD. Otherwise the note is NOTED
 * and err is cleared. deduped and bytes_moved stay false on every path.
 * Dedup across realms moves no bytes.
 */
SwarmNotNoDedupResult SwarmNoteNotNoDedup(const SwarmNotNoDedup& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODEDUP_H
