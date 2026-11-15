// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmanifestcap.h>

namespace modelnet {

SwarmNotManifestCapResult SwarmNoteNotManifestCap(const SwarmNotManifestCap& note, std::string& err)
{
    // The flat manifest cap is 16384 bytes and this note stores nothing.
    SwarmNotManifestCapResult result;
    result.stored = false;
    result.bytes_moved = false;
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
