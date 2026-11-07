// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflat16k.h>

#include <string>

namespace modelnet {

SwarmNotNoFlat16kResult SwarmNoteNotNoFlat16k(const SwarmNotNoFlat16k& note, std::string& err)
{
    SwarmNotNoFlat16kResult result;
    result.flattened = false;
    if (note.manifest_id.empty()) {
        result.code = "MANIFEST";
        result.flattened = false;
        err = "MANIFEST";
        return result;
    }
    // The flat manifest cap is 16384. Count greater than 16384 is not flat.
    // This note flattens nothing.
    if (note.count > 16384) {
        result.code = "NOT_FLAT";
        result.flattened = false;
        err = "NOT_FLAT";
        return result;
    }
    if (note.want_flatten) {
        result.code = "HELD";
        result.flattened = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.flattened = false;
    err.clear();
    return result;
}

} // namespace modelnet
