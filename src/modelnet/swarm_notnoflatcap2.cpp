// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflatcap2.h>

#include <string>

namespace modelnet {

SwarmNotNoFlatCap2Result SwarmNoteNotNoFlatCap2(const SwarmNotNoFlatCap2& note, std::string& err)
{
    SwarmNotNoFlatCap2Result result;
    result.stored = false;
    // A flat manifest stays capped at 16384 entries and this note stores nothing.
    if (note.manifest_id.empty()) {
        result.code = "MANIFEST";
        result.stored = false;
        err = "MANIFEST";
        return result;
    }
    if (note.entries > 16384) {
        result.code = "CAPPED";
        result.stored = false;
        err = "CAPPED";
        return result;
    }
    if (note.want_store) {
        result.code = "CAPPED";
        result.stored = false;
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    err.clear();
    return result;
}

} // namespace modelnet
