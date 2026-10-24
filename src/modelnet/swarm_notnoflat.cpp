// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflat.h>

#include <string>

namespace modelnet {

SwarmNotNoFlatResult SwarmNoteNotNoFlat(const SwarmNotNoFlat& note, std::string& err)
{
    SwarmNotNoFlatResult result;
    result.stored = false;
    result.bytes_moved = false;
    // A flat manifest other than 16384 bytes is not stored.
    if (note.manifest_id.empty()) {
        result.code = "MANIFEST";
        result.stored = false;
        result.bytes_moved = false;
        err = "MANIFEST";
        return result;
    }
    if (note.size_bytes != 16384) {
        result.code = "CAPPED";
        result.stored = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_store) {
        result.code = "CAPPED";
        result.stored = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
