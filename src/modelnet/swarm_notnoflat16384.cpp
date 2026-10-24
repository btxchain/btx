// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflat16384.h>

#include <string>

namespace modelnet {

SwarmNotNoFlat16384Result SwarmNoteNotNoFlat16384(const SwarmNotNoFlat16384& note, std::string& err)
{
    SwarmNotNoFlat16384Result result;
    // The flat manifest cap stays 16384 bytes.
    result.raised = false;
    result.bytes = 16384;
    if (note.manifest_id.empty()) {
        result.code = "MANIFEST";
        result.raised = false;
        result.bytes = 16384;
        err = "MANIFEST";
        return result;
    }
    if (note.want_raise) {
        result.code = "HELD";
        result.raised = false;
        result.bytes = 16384;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.bytes = 16384;
    err.clear();
    return result;
}

} // namespace modelnet
