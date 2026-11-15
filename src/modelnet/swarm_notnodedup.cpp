// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodedup.h>

#include <string>

namespace modelnet {

SwarmNotNoDedupResult SwarmNoteNotNoDedup(const SwarmNotNoDedup& note, std::string& err)
{
    SwarmNotNoDedupResult result;
    result.deduped = false;
    result.bytes_moved = false;
    // Dedup across realms moves no bytes.
    // deduped and bytes_moved stay false on every path.
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        result.deduped = false;
        result.bytes_moved = false;
        err = "PIECE";
        return result;
    }
    if (note.other_realm) {
        result.code = "DEDUP_PRIVATE";
        result.deduped = false;
        result.bytes_moved = false;
        err = "DEDUP_PRIVATE";
        return result;
    }
    if (note.want_dedup) {
        result.code = "HELD";
        result.deduped = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.deduped = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
