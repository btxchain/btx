// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomanifest.h>

#include <string>

namespace modelnet {

SwarmNotNoManifestResult SwarmNoteNotNoManifest(const SwarmNotNoManifest& note, std::string& err)
{
    SwarmNotNoManifestResult result;
    result.accepted = false;
    result.bytes_moved = false;
    // A flat manifest over 16384 entries is not accepted and moves no bytes.
    if (note.manifest_id.empty()) {
        result.code = "MANIFEST";
        result.accepted = false;
        result.bytes_moved = false;
        err = "MANIFEST";
        return result;
    }
    if (note.over_cap) {
        result.code = "CAPPED";
        result.accepted = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_accept) {
        result.code = "CAPPED";
        result.accepted = false;
        result.bytes_moved = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
