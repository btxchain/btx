// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifestcap.h>

#include <cstdint>

namespace modelnet {

SwarmManifestCapResult SwarmNoteManifestCap(const SwarmManifestCap& note, std::string& err)
{
    SwarmManifestCapResult result;
    result.accepted = false;
    if (note.manifest_id.empty() || note.piece_count < 0) {
        result.code = "MANIFEST";
        err = "MANIFEST";
        return result;
    }
    // MANIFEST_CAP wins even when want_accept is true.
    if (note.piece_count > SWARM_MANIFEST_COUNT_CAP) {
        result.code = "MANIFEST_CAP";
        result.accepted = false;
        err = "MANIFEST_CAP";
        return result;
    }
    // This note does not accept a manifest.
    if (note.want_accept) {
        result.code = "HELD";
        result.accepted = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
